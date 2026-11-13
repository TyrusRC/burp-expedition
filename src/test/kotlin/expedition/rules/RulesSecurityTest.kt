package expedition.rules

import expedition.analysis.HttpExchanges
import expedition.engine.ListenerConfig
import expedition.engine.TcpListener
import expedition.engine.TestCa
import expedition.engine.waitUntil
import expedition.export.HarCodec
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.net.URI
import java.nio.file.Files
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket

/** N1-N7 hardening: bodyFile sandbox, header injection, framing ambiguity, redirect/webhook safety, HAR pairing. */
class RulesSecurityTest {
    @TempDir lateinit var tempDir: File

    private val boss = NioEventLoopGroup(1)
    private val worker = NioEventLoopGroup()
    private val registry = ConnectionRegistry()
    private val engine = RulesEngine()
    private val upstream = FakeHttpServer("A")
    private val closeables = ArrayList<AutoCloseable>()

    private fun listen(upPort: Int = upstream.port): Int {
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }.also { it.rulesEngine = engine }
        val l = TcpListener(ListenerConfig("web", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", upPort), registry, boss, worker, gate)
        closeables += AutoCloseable { l.stop() }
        return (l.start().sync().channel().localAddress() as java.net.InetSocketAddress).port
    }

    private fun client(port: Int) = Socket("127.0.0.1", port).also { it.soTimeout = 5000; closeables += it }
    private fun Socket.send(s: String) { getOutputStream().write(s.toByteArray(Charsets.ISO_8859_1)); getOutputStream().flush() }
    private fun Socket.read() = Wire.read(getInputStream())!!
    private fun add(json: String) = engine.add(RuleCodec.fromJson(json))
    private fun notes() = registry.allMessages().filter { it.isNote }.map { it.dissectedView!! }

    @AfterEach
    fun tearDown() {
        closeables.reversed().forEach { runCatching { it.close() } }
        upstream.close()
        boss.shutdownGracefully(0, 100, java.util.concurrent.TimeUnit.MILLISECONDS).sync()
        worker.shutdownGracefully(0, 100, java.util.concurrent.TimeUnit.MILLISECONDS).sync()
    }

    // ── N2: bodyFile ────────────────────────────────────────────────────

    private fun mockFile(path: String) = RuleCodec.fromJson("""{"match":{},"actions":[{"type":"mock","bodyFile":${expedition.server.Json.value(path)}}]}""")

    @Test
    fun `bodyFile is confined to the rules-files directory, bounded and read once`() {
        val dir = RulesTestFiles.dir
        val f = RulesTestFiles.file("ok.json", "{\"a\":1}".toByteArray())
        val rule = mockFile("ok.json")
        f.writeText("changed later")
        assertEquals("{\"a\":1}", String((rule.actions[0] as RuleAction.MockResponse).body.bytes()), "cached at creation, not re-read")
        assertEquals("changed later", String((mockFile(f.path).actions[0] as RuleAction.MockResponse).body.bytes()), "absolute path inside the sandbox")

        val outside = File(tempDir, "secret").apply { writeText("id_rsa") }
        assertThrows<IllegalArgumentException> { mockFile(outside.path) }
        assertThrows<IllegalArgumentException> { mockFile("../" + outside.name) }
        assertThrows<IllegalArgumentException> { mockFile("/etc/passwd") }
        assertThrows<IllegalArgumentException> { mockFile("/dev/zero") }
        assertThrows<IllegalArgumentException> { mockFile("missing.bin") }
        File(dir, "sub").mkdirs()
        assertThrows<IllegalArgumentException> { mockFile("sub") }

        val link = File(dir, "link-out")
        runCatching { Files.deleteIfExists(link.toPath()); Files.createSymbolicLink(link.toPath(), outside.toPath()) }.onSuccess {
            assertThrows<IllegalArgumentException> { mockFile("link-out") }
        }
        val devLink = File(dir, "zero")
        runCatching { Files.deleteIfExists(devLink.toPath()); Files.createSymbolicLink(devLink.toPath(), File("/dev/zero").toPath()) }.onSuccess {
            assertThrows<IllegalArgumentException> { mockFile("zero") }
        }
        val fifo = File(dir, "fifo")
        if (!fifo.exists()) runCatching { ProcessBuilder("mkfifo", fifo.path).start().waitFor() }
        if (fifo.exists()) assertThrows<IllegalArgumentException> { mockFile("fifo") }

        val big = File(dir, "big.bin")
        java.io.RandomAccessFile(big, "rw").use { it.setLength(RuleFiles.MAX_BYTES + 1L) }
        val e = assertThrows<IllegalArgumentException> { mockFile("big.bin") }
        assertTrue(e.message!!.contains("larger"), e.message)
        big.delete()
    }

    // ── N7: header injection + ambiguous framing ────────────────────────

    @Test
    fun `transforms and mocks refuse CR, LF or NUL in header names and values`() {
        assertThrows<IllegalArgumentException> {
            RuleCodec.fromJson("""{"match":{},"actions":[{"type":"transformRequest","setHeaders":{"X-A":"1\r\nX-Injected: 1"}}]}""")
        }
        assertThrows<IllegalArgumentException> {
            RuleCodec.fromJson("""{"match":{},"actions":[{"type":"transformResponse","setHeaders":[["X-A\nB","1"]]}]}""")
        }
        assertThrows<IllegalArgumentException> {
            RuleCodec.fromJson("""{"match":{},"actions":[{"type":"mock","headers":{"Set-Cookie":"a=1\r\n\r\nGET /smuggled HTTP/1.1"}}]}""")
        }
        assertThrows<IllegalArgumentException> { RuleCodec.fromJson("""{"match":{},"actions":[{"type":"mock","reason":"OK\r\nX: 1"}]}""") }
        RuleCodec.fromJson("""{"match":{},"actions":[{"type":"transformRequest","setHeaders":{"X-A":"fine value; with: colons"}}]}""")
    }

    private fun parse(req: String): List<HttpEvent> = HttpStreamParser(true).let { p -> p.feed(req.toByteArray(Charsets.ISO_8859_1)) }

    private fun rawReason(req: String): String? {
        val p = HttpStreamParser(true)
        val ev = p.feed(req.toByteArray(Charsets.ISO_8859_1))
        return if (ev.any { it is HttpEvent.Raw }) p.rawReason else null
    }

    @Test
    fun `parser goes raw on ambiguous request framing and says why`() {
        val h = "POST / HTTP/1.1\r\nHost: x\r\n"
        val amb = HttpStreamParser.REASON_AMBIGUOUS
        assertTrue(rawReason("${h}Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")!!.startsWith(amb))
        assertTrue(rawReason("${h}Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")!!.startsWith(amb))
        assertTrue(rawReason("${h}Transfer-Encoding: xchunked\r\n\r\n")!!.startsWith(amb))
        assertTrue(rawReason("${h}Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n")!!.startsWith(amb))
        assertTrue(rawReason("${h}Content-Length: 3\r\nContent-Length: 4\r\n\r\nabcd")!!.startsWith(amb))
        assertTrue(rawReason("${h}Content-Length: +3\r\n\r\nabc")!!.startsWith(amb))
        assertTrue(rawReason("${h}X-A: 1\r\n folded\r\nContent-Length: 0\r\n\r\n")!!.startsWith(amb))
        assertTrue(rawReason("${h}X-A: a\u0000b\r\n\r\n")!!.startsWith(amb))
        assertTrue(rawReason("${h}X-A: a\nTransfer-Encoding: chunked\r\n\r\n")!!.startsWith(amb))
        assertEquals(HttpStreamParser.REASON_HTTP2, rawReason("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
        // Unambiguous forms still parse.
        assertNull(rawReason("${h}Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"))
        assertNull(rawReason("${h}Content-Length: 3\r\nContent-Length: 3\r\n\r\nabc"))
        assertTrue(parse("${h}Content-Length: 3\r\n\r\nabc").last() == HttpEvent.End)
    }

    @Test
    fun `TE plus CL request bypasses rules to a raw relay with a warning note`() {
        add("""{"match":{},"actions":[{"type":"mock","body":"mocked"}]}""")
        val c = client(listen())
        c.send(get("/first"))
        assertEquals("mocked", c.read().body)
        // The upstream reads Content-Length:0 framing as it likes; the proxy must not split it into slots.
        c.send("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        waitUntil { notes().any { it.startsWith("RULES BYPASSED: ${HttpStreamParser.REASON_AMBIGUOUS}: both Transfer-Encoding and Content-Length") } }
        waitUntil { upstream.requests.isNotEmpty() }
        assertEquals("/x", upstream.requests.first().target, "relayed raw, not mocked")
    }

    private fun get(path: String, extra: String = "") = "GET $path HTTP/1.1\r\nHost: app.test\r\n$extra\r\n"

    // ── N3: redirect / webhook ──────────────────────────────────────────

    @Test
    fun `redirect to another host strips credentials unless forwardCredentials`() {
        FakeHttpServer("B").use { b ->
            add("""{"match":{"path":"/plain"},"actions":[{"type":"redirect","url":"http://127.0.0.1:${b.port}"}]}""")
            add("""{"match":{"path":"/creds"},"actions":[{"type":"redirect","url":"http://127.0.0.1:${b.port}","forwardCredentials":true}]}""")
            val c = client(listen())
            val secret = "Authorization: Bearer s3cret\r\nCookie: sid=1\r\nProxy-Authorization: Basic eA==\r\n"
            c.send(get("/plain", secret)); assertEquals("B", c.read().header("x-upstream"))
            c.send(get("/creds", secret)); assertEquals("B", c.read().header("x-upstream"))
            val (plain, creds) = b.requests.toList()
            assertNull(plain.headers["authorization"]); assertNull(plain.headers["cookie"]); assertNull(plain.headers["proxy-authorization"])
            assertEquals("Bearer s3cret", creds.headers["authorization"]); assertEquals("sid=1", creds.headers["cookie"])
            assertTrue(notes().any { it.contains("credentials NOT forwarded") })
        }
    }

    @Test
    fun `redirect to the same upstream host and port keeps credentials`() {
        add("""{"match":{"path":"/same"},"actions":[{"type":"redirect","url":"http://127.0.0.1:${upstream.port}"}]}""")
        val c = client(listen())
        c.send(get("/same", "Authorization: Bearer k\r\n")); c.read()
        assertEquals("Bearer k", upstream.requests.single().headers["authorization"])
    }

    private fun tlsServer(): SSLServerSocket {
        val ks = KeyStore.getInstance("PKCS12").apply { TestCa.keystore(tempDir, "selfsigned.test", ca = false).inputStream().use { load(it, TestCa.password) } }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, TestCa.password) }
        val server = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }.serverSocketFactory.createServerSocket(0) as SSLServerSocket
        closeables += server
        Thread {
            while (true) {
                val s = try { server.accept() } catch (_: Exception) { break }
                Thread {
                    runCatching {
                        s.use {
                            Wire.read(it.getInputStream())
                            it.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray()); it.getOutputStream().flush()
                        }
                    }
                }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true }.start()
        return server
    }

    @Test
    fun `outbound TLS verifies certificates unless insecureTls`() {
        val server = tlsServer()
        val url = URI("https://127.0.0.1:${server.localPort}/")
        val req = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".toByteArray()
        assertThrows<IOException> { OutboundHttp.send(url, req, "GET", 5000) }
        assertEquals(200, OutboundHttp.send(url, req, "GET", 5000, insecure = true).head.status)

        add("""{"match":{"path":"/v"},"actions":[{"type":"redirect","url":"$url"}]}""")
        add("""{"match":{"path":"/i"},"actions":[{"type":"redirect","url":"$url","insecureTls":true}]}""")
        val c = client(listen())
        c.send(get("/v")); assertEquals(502, c.read().status)
        c.send(get("/i")); assertEquals("ok", c.read().body)
    }

    @Test
    fun `local and metadata addresses are classified as local`() {
        fun local(a: String) = OutboundHttp.isLocalAddress(InetAddress.getByName(a))
        listOf("127.0.0.1", "127.9.9.9", "::1", "169.254.169.254", "fe80::1", "fd00:ec2::254", "fc00::1", "0.0.0.0", "::ffff:127.0.0.1", "100.100.100.200")
            .forEach { assertTrue(local(it), it) }
        listOf("8.8.8.8", "10.0.0.1", "192.168.1.1", "2001:4860:4860::8888").forEach { assertFalse(local(it), it) }
    }

    @Test
    fun `webhooks to local addresses are refused unless allowLocal, credentials redacted unless asked`() {
        val hook = com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1", 0), 0)
        val payloads = java.util.concurrent.CopyOnWriteArrayList<String>()
        hook.createContext("/") { ex ->
            payloads += ex.requestBody.readBytes().toString(Charsets.UTF_8)
            val out = """{"status":202,"body":"from hook"}""".toByteArray()
            ex.sendResponseHeaders(200, out.size.toLong()); ex.responseBody.use { it.write(out) }
        }
        hook.start()
        try {
            engine.webhooksEnabled = true
            val u = "http://127.0.0.1:${hook.address.port}/cb"
            add("""{"match":{"path":"/blocked"},"actions":[{"type":"webhook","url":"$u","respond":true}]}""")
            add("""{"match":{"path":"/allowed"},"actions":[{"type":"webhook","url":"$u","respond":true,"allowLocal":true}]}""")
            add("""{"match":{"path":"/fwd"},"actions":[{"type":"webhook","url":"$u","respond":true,"allowLocal":true,"forwardCredentials":true}]}""")
            val c = client(listen())
            c.send(get("/blocked")); assertEquals("A:GET /blocked body=", c.read().body)
            assertTrue(payloads.isEmpty(), "SSRF to loopback refused by default")
            c.send(get("/allowed", "Cookie: sid=topsecret\r\n")); assertEquals("from hook", c.read().body)
            assertFalse(payloads.single().contains("topsecret")); assertTrue(payloads.single().contains("[redacted]"))
            c.send(get("/fwd", "Cookie: sid=topsecret\r\n")); assertEquals("from hook", c.read().body)
            assertTrue(payloads[1].contains("topsecret"))
        } finally { hook.stop(0) }
    }

    @Test
    fun `codec round-trips the new safety flags`() {
        val r = RuleCodec.fromJson("""{"match":{},"actions":[
            {"type":"redirect","url":"https://h:1","forwardCredentials":true,"insecureTls":true},
            {"type":"webhook","url":"http://h/","allowLocal":true,"forwardCredentials":true,"insecureTls":true}]}""")
        assertEquals(RuleAction.Redirect("https://h:1", false, forwardCredentials = true, insecureTls = true), r.actions[0])
        assertEquals(RuleAction.Webhook("http://h/", false, allowLocal = true, forwardCredentials = true, insecureTls = true), r.actions[1])
        assertEquals(r, RuleCodec.fromJson(RuleCodec.toJson(r)))
        val d = RuleCodec.fromJson("""{"match":{},"actions":[{"type":"redirect","url":"https://h:1"},{"type":"webhook","url":"http://h/"}]}""")
        assertEquals(RuleAction.Redirect("https://h:1"), d.actions[0])
        assertEquals(RuleAction.Webhook("http://h/"), d.actions[1])
    }

    // ── N4: HAR / exchange pairing ──────────────────────────────────────

    @Test
    fun `pipelined requests with a mock in the middle export as three correctly paired exchanges`() {
        add("""{"match":{"path":"/mock"},"actions":[{"type":"mock","status":418,"body":"teapot"}]}""")
        val c = client(listen())
        c.send(get("/one") + get("/mock") + get("/three"))
        assertEquals("A:GET /one body=", c.read().body)
        assertEquals("teapot", c.read().body)
        assertEquals("A:GET /three body=", c.read().body)
        val conn = registry.allConnections().single().connectionId
        waitUntil { HttpExchanges.extract(conn, registry.messagesFor(conn)).count { it.response != null } == 3 }
        val ex = HttpExchanges.extract(conn, registry.messagesFor(conn))
        assertEquals(listOf("GET /one -> 200", "GET /mock -> 418", "GET /three -> 200"), ex.map { it.label })
        assertEquals("teapot", String(ex[1].response!!.body))
        assertEquals("A:GET /three body=", String(ex[2].response!!.body))
        assertEquals(listOf("/one", "/three"), upstream.requests.map { it.target }, "mock never sent upstream")
        assertTrue(notes().any { it.startsWith("MOCKED by rule") })

        val har = HarCodec.export(registry, conn)
        assertEquals(3, har.entries)
        val json = expedition.server.Json.asObject(expedition.server.Json.parse(har.json))
        val entries = expedition.server.Json.asObject(json["log"])["entries"] as List<*>
        assertEquals(3, entries.size)
        val statuses = entries.map { (expedition.server.Json.asObject(expedition.server.Json.asObject(it)["response"])["status"] as Number).toInt() }
        assertEquals(listOf(200, 418, 200), statuses)
    }

    @Test
    fun `a redirected request pairs with the redirect target's response`() {
        FakeHttpServer("B").use { b ->
            add("""{"match":{"path":"/r"},"actions":[{"type":"redirect","url":"http://127.0.0.1:${b.port}"}]}""")
            val c = client(listen())
            c.send(get("/r") + get("/after"))
            assertEquals("B", c.read().header("x-upstream"))
            assertEquals("A:GET /after body=", c.read().body)
            val conn = registry.allConnections().single().connectionId
            waitUntil { HttpExchanges.extract(conn, registry.messagesFor(conn)).count { it.response != null } == 2 }
            val ex = HttpExchanges.extract(conn, registry.messagesFor(conn))
            assertEquals(listOf("/r", "/after"), ex.map { it.request.target })
            assertEquals("B", ex[0].response!!.header("x-upstream"))
            assertEquals("A", ex[1].response!!.header("x-upstream"))
        }
    }
}
