package expedition.rules

import expedition.engine.ListenerConfig
import expedition.engine.TcpEchoServer
import expedition.engine.TcpListener
import expedition.engine.waitUntil
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.Socket
import java.net.SocketTimeoutException

/** End-to-end: real Netty TCP listener + MessageGate + RulesEngine in front of a fake HTTP upstream. */
class RulesListenerTest {
    private val boss = NioEventLoopGroup(1)
    private val worker = NioEventLoopGroup()
    private val registry = ConnectionRegistry()
    private val intercept = InterceptController()
    private val engine = RulesEngine()
    private val upstream = FakeHttpServer("A")
    private val closeables = ArrayList<AutoCloseable>()
    private val listeners = ArrayList<TcpListener>()

    private fun listen(upPort: Int = upstream.port, name: String = "web", rules: RulesEngine? = engine): Int {
        val gate = MessageGate(registry, intercept, MatchReplaceEngine()) { _, _, _, _ -> }.also { it.rulesEngine = rules }
        val l = TcpListener(ListenerConfig(name, Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", upPort), registry, boss, worker, gate)
        listeners += l
        return (l.start().sync().channel().localAddress() as java.net.InetSocketAddress).port
    }

    private fun client(port: Int, timeoutMs: Int = 5000) = Socket("127.0.0.1", port).also { it.soTimeout = timeoutMs; closeables += it }
    private fun Socket.send(s: String) { getOutputStream().write(s.toByteArray(Charsets.ISO_8859_1)); getOutputStream().flush() }
    private fun Socket.read(head: Boolean = false) = Wire.read(getInputStream(), head)!!

    private fun get(path: String, extra: String = "") = "GET $path HTTP/1.1\r\nHost: app.test\r\n$extra\r\n"
    private fun add(json: String) = engine.add(RuleCodec.fromJson(json))

    @AfterEach
    fun tearDown() {
        closeables.forEach { runCatching { it.close() } }
        listeners.forEach { runCatching { it.stop() } }
        upstream.close()
        boss.shutdownGracefully(0, 100, java.util.concurrent.TimeUnit.MILLISECONDS).sync()
        worker.shutdownGracefully(0, 100, java.util.concurrent.TimeUnit.MILLISECONDS).sync()
    }

    @Test
    fun `without rules keep-alive traffic and non-HTTP bytes pass unchanged`() {
        val port = listen()
        val c = client(port)
        c.send(get("/one") + "POST /two HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
        assertEquals("A:GET /one body=", c.read().body)
        assertEquals("A:POST /two body=abc", c.read().body)
        c.send(get("/chunked"))
        assertEquals("A:GET /chunked body=", c.read().body)
        assertEquals(3, upstream.requests.size)
        assertEquals(1, upstream.accepted.get())

        TcpEchoServer().use { echo ->
            val e = client(listen(echo.port, "raw"))
            e.send("\u0000\u0001binary\r\n\r\n")
            assertEquals("\u0000\u0001binary\r\n\r\n", String(e.getInputStream().readNBytes(12), Charsets.ISO_8859_1))
        }
    }

    @Test
    fun `non-HTTP protocols are not stalled when rules are active`() {
        add("""{"match":{},"actions":[{"type":"mock","status":500}]}""")
        TcpEchoServer().use { echo ->
            val c = client(listen(echo.port, "smtp"), 2000)
            c.send("EHLO example.org\r\n")
            assertEquals("EHLO example.org\r\n", String(c.getInputStream().readNBytes(18), Charsets.ISO_8859_1))
            c.send("\u0016\u0003\u0001")
            assertEquals("\u0016\u0003\u0001", String(c.getInputStream().readNBytes(3), Charsets.ISO_8859_1))
        }
    }

    @Test
    fun `mock answers the client directly and never sends the request upstream`() {
        add("""{"name":"m","match":{"method":"GET","path":"/mock*"},"actions":[{"type":"mock","status":418,"headers":{"X-Mock":"1"},"body":"teapot"}]}""")
        val c = client(listen())
        c.send(get("/mock"))
        val r = c.read()
        assertEquals(418, r.status)
        assertEquals("1", r.header("x-mock"))
        assertEquals("teapot", r.body)
        Thread.sleep(150)
        assertEquals(0L, upstream.bytesReceived.get(), "no byte of the mocked request may reach the upstream")
        // same keep-alive connection: a non-matching request still reaches the upstream
        c.send(get("/real"))
        assertEquals("A:GET /real body=", c.read().body)
        assertEquals(listOf("/real"), upstream.requests.map { it.target })
        assertEquals(1, engine.hitCount(engine.rules().single().id))
        waitUntil { registry.allMessages().any { it.dissectedView?.startsWith("MOCKED by rule 'm'") == true } }
    }

    @Test
    fun `pipelined keep-alive requests get responses in request order (mock, upstream, chunked)`() {
        add("""{"match":{"path":"/m/*"},"actions":[{"type":"mock","body":"mocked"}]}""")
        val c = client(listen())
        c.send(get("/a") + get("/m/1") + "POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n" + get("/m/2") + get("/chunked"))
        assertEquals("A:GET /a body=", c.read().body)
        assertEquals("mocked", c.read().body)
        assertEquals("A:POST /b body=hi", c.read().body)
        assertEquals("mocked", c.read().body)
        assertEquals("A:GET /chunked body=", c.read().body)
        assertEquals(listOf("/a", "/b", "/chunked"), upstream.requests.map { it.target })
    }

    @Test
    fun `request bytes split into tiny writes are still matched`() {
        add("""{"match":{"method":"POST","bodyRegex":"secret"},"actions":[{"type":"mock","status":403}]}""")
        val c = client(listen())
        val req = "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\nmy secret"
        req.chunked(3).forEach { c.send(it); Thread.sleep(2) }
        assertEquals(403, c.read().status)
        c.send("POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nfine")
        assertEquals("A:POST /x body=fine", c.read().body)
    }

    @Test
    fun `delay holds the request for at least the configured time`() {
        add("""{"match":{"path":"/slow"},"actions":[{"type":"delay","ms":400}]}""")
        val c = client(listen())
        c.send(get("/fast"))
        c.read()
        val t0 = System.nanoTime()
        c.send(get("/slow"))
        assertEquals("A:GET /slow body=", c.read().body)
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertTrue(ms >= 400, "took only $ms ms")
        val t1 = System.nanoTime()
        c.send(get("/fast"))
        c.read()
        assertTrue((System.nanoTime() - t1) / 1_000_000 < 400, "a non-matching request must not be delayed")
    }

    @Test
    fun `timeout never answers and never forwards`() {
        add("""{"match":{"path":"/hang"},"actions":[{"type":"timeout"}]}""")
        val c = client(listen(), 600)
        c.send(get("/hang"))
        assertThrows<SocketTimeoutException> { c.getInputStream().read() }
        assertEquals(0L, upstream.bytesReceived.get())
    }

    @Test
    fun `close ends the connection with FIN, reset with RST`() {
        add("""{"match":{"path":"/close"},"actions":[{"type":"close"}]}""")
        add("""{"match":{"path":"/reset"},"actions":[{"type":"reset"}]}""")
        val port = listen()
        val c = client(port)
        c.send(get("/close"))
        assertEquals(-1, c.getInputStream().read())

        val r = client(port)
        r.send(get("/reset"))
        val e = assertThrows<java.net.SocketException> {
            // a RST surfaces as "Connection reset" on read (never a clean -1)
            while (r.getInputStream().read() >= 0) { /* drain */ }
            throw AssertionError("clean EOF instead of reset")
        }
        assertTrue(e.message!!.contains("reset", ignoreCase = true), e.message)
        assertEquals(0L, upstream.bytesReceived.get())
    }

    @Test
    fun `redirect sends the request to another upstream and relays its answer`() {
        FakeHttpServer("B").use { b ->
            add("""{"match":{"path":"/api/*"},"actions":[{"type":"redirect","url":"http://127.0.0.1:${b.port}"}]}""")
            val c = client(listen())
            c.send("POST /api/x HTTP/1.1\r\nHost: app.test\r\nContent-Length: 3\r\n\r\nabc" + get("/local"))
            val r = c.read()
            assertEquals("B", r.header("x-upstream"))
            assertEquals("B:POST /api/x body=abc", r.body)
            assertEquals("127.0.0.1:${b.port}", r.header("x-echo-host"))
            assertEquals("A:GET /local body=", c.read().body)
            assertEquals(listOf("/local"), upstream.requests.map { it.target })
        }
    }

    @Test
    fun `transforms rewrite request url, headers, chunked body and the response`() {
        add("""{"match":{"path":"/t*"},"actions":[
            {"type":"transformRequest","setHeaders":[["X-Added","yes"]],"removeHeaders":["X-Drop"],
             "replace":[{"regex":"world","with":"rules"}],"urlReplace":{"regex":"^/t","with":"/chunked-t"}},
            {"type":"transformResponse","status":299,"setHeaders":{"X-Resp":"1"},"replace":[{"regex":"A:","with":"upstream:"}]}]}""")
        val c = client(listen())
        c.send("POST /t1 HTTP/1.1\r\nHost: x\r\nX-Drop: 1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        val r = c.read()
        assertEquals(299, r.status)
        assertEquals("1", r.header("x-resp"))
        assertEquals("upstream:POST /chunked-t1 body=hello rules", r.body)
        val seen = upstream.requests.single()
        assertEquals("yes", seen.headers["x-added"])
        assertNull(seen.headers["x-drop"])
        assertEquals("11", seen.headers["content-length"])
    }

    @Test
    fun `times limits a rule, disabled and other-listener rules have no effect`() {
        add("""{"times":1,"match":{"path":"/once"},"actions":[{"type":"mock","body":"first"}]}""")
        add("""{"enabled":false,"match":{},"actions":[{"type":"close"}]}""")
        add("""{"match":{"listener":"elsewhere"},"actions":[{"type":"close"}]}""")
        val c = client(listen())
        c.send(get("/once")); assertEquals("first", c.read().body)
        c.send(get("/once")); assertEquals("A:GET /once body=", c.read().body)
    }

    @Test
    fun `chained non-terminal rules apply in order, first terminal rule wins`() {
        add("""{"match":{},"actions":[{"type":"transformRequest","setHeaders":{"X-One":"1"}}]}""")
        add("""{"match":{"headers":[{"name":"X-One"}],"path":"/m"},"actions":[{"type":"mock","body":"second"}]}""")
        add("""{"match":{"path":"/m"},"actions":[{"type":"mock","body":"third"}]}""")
        val c = client(listen())
        c.send(get("/m")); assertEquals("second", c.read().body)
        c.send(get("/p")); assertEquals("1", c.read().header("x-echo-x-one"))
    }

    @Test
    fun `response rules can replace upstream responses by status and body`() {
        add("""{"match":{"direction":"response","path":"/chunked","bodyRegex":"GET"},"actions":[{"type":"mock","status":503,"body":"replaced"}]}""")
        val c = client(listen())
        c.send(get("/chunked")); assertEquals("replaced", c.read().body)
        c.send(get("/other")); assertEquals("A:GET /other body=", c.read().body)
        assertEquals(2, upstream.requests.size)
    }

    @Test
    fun `HEAD request mocked with Content-Length but no body keeps the connection usable`() {
        add("""{"match":{"method":"HEAD"},"actions":[{"type":"mock","body":"12345"}]}""")
        val c = client(listen())
        c.send("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n" + get("/after"))
        val h = c.read(head = true)
        assertEquals("5", h.header("content-length"))
        assertEquals("A:GET /after body=", c.read().body)
    }

    @Test
    fun `breakpoint holds the request in intercept even while intercept is off`() {
        add("""{"match":{"path":"/bp"},"actions":[{"type":"breakpoint"}]}""")
        assertTrue(!intercept.isEnabled())
        val c = client(listen())
        c.send(get("/bp"))
        waitUntil { intercept.heldMessages().isNotEmpty() }
        val held = intercept.heldMessages().single()
        assertEquals(Direction.CLIENT_TO_UPSTREAM.name, held.direction)
        assertEquals(0, upstream.requests.size)
        intercept.forward(held.id, String(held.bytes).replace("/bp", "/edited").toByteArray())
        assertEquals("A:GET /edited body=", c.read().body)
    }

    @Test
    fun `websocket upgrade switches the connection to raw passthrough`() {
        add("""{"match":{},"actions":[{"type":"transformRequest","setHeaders":{"X-Seen":"1"}}]}""")
        val c = client(listen())
        c.send(get("/ws", "Upgrade: websocket\r\nConnection: Upgrade\r\n"))
        assertEquals(101, c.read().status)
        assertEquals("1", upstream.requests.single().headers["x-seen"])
        val frame = "\u0081\u0005GET / HTTP/1.1\r\n\r\n"
        c.send(frame)
        assertEquals(frame, String(c.getInputStream().readNBytes(frame.length), Charsets.ISO_8859_1))
        assertEquals(1, upstream.requests.size, "bytes after 101 are not parsed as HTTP")
    }

    @Test
    fun `webhook with respond turns the callback reply into the response, only when enabled`() {
        val hook = com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1", 0), 0)
        val payloads = java.util.concurrent.CopyOnWriteArrayList<String>()
        hook.createContext("/") { ex ->
            payloads += ex.requestBody.readBytes().toString(Charsets.UTF_8)
            val out = """{"status":202,"headers":{"X-Hook":"1"},"body":"from hook"}""".toByteArray()
            ex.sendResponseHeaders(200, out.size.toLong()); ex.responseBody.use { it.write(out) }
        }
        hook.start()
        try {
            add("""{"match":{"path":"/h"},"actions":[{"type":"webhook","url":"http://127.0.0.1:${hook.address.port}/cb","respond":true,"allowLocal":true}]}""")
            val c = client(listen())
            c.send(get("/h")); assertEquals("A:GET /h body=", c.read().body, "webhooks are off by default")
            assertTrue(payloads.isEmpty())
            engine.webhooksEnabled = true
            c.send(get("/h"))
            val r = c.read()
            assertEquals(202, r.status); assertEquals("1", r.header("x-hook")); assertEquals("from hook", r.body)
            assertTrue(payloads.single().contains("\"path\":\"/h\""))
            assertEquals(1, upstream.requests.size)
        } finally { hook.stop(0) }
    }

    @Test
    fun `redirect to an unreachable target answers 502 and keeps the connection`() {
        val dead = java.net.ServerSocket(0).use { it.localPort }
        add("""{"match":{"path":"/r"},"actions":[{"type":"redirect","url":"http://127.0.0.1:$dead"}]}""")
        val c = client(listen())
        c.send(get("/r"))
        assertEquals(502, c.read().status)
        c.send(get("/ok")); assertEquals("A:GET /ok body=", c.read().body)
    }

    @Test
    fun `rules added mid-connection apply to the next request on the same keep-alive connection`() {
        val c = client(listen())
        c.send(get("/x")); assertEquals("A:GET /x body=", c.read().body)
        add("""{"match":{"path":"/x"},"actions":[{"type":"mock","body":"now mocked"}]}""")
        c.send(get("/x")); assertEquals("now mocked", c.read().body)
        engine.clear()
        c.send(get("/x")); assertEquals("A:GET /x body=", c.read().body)
    }
}
