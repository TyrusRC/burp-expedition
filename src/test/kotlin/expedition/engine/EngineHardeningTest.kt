package expedition.engine

import expedition.engine.tls.SniTlsRouter
import expedition.intercept.InterceptController
import expedition.intercept.InterceptDecision
import expedition.intercept.StreamKey
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import expedition.rules.RuleCodec
import expedition.rules.RulesEngine
import expedition.rules.Wire
import expedition.tls.BurpCertificateProvider
import io.netty.buffer.Unpooled
import io.netty.channel.embedded.EmbeddedChannel
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/** ALPN, upstream leak, SNI flood, UDP cap, stop-closes-connections, lazy dial for mocks, held cleanup. */
class EngineHardeningTest {
    @TempDir lateinit var tempDir: File
    private lateinit var boss: NioEventLoopGroup
    private lateinit var worker: NioEventLoopGroup
    private val closeables = ArrayList<AutoCloseable>()

    @BeforeEach
    fun setUp() { boss = NioEventLoopGroup(1); worker = NioEventLoopGroup() }

    @AfterEach
    fun tearDown() {
        closeables.reversed().forEach { runCatching { it.close() } }
        boss.shutdownGracefully(0, 100, TimeUnit.MILLISECONDS).sync()
        worker.shutdownGracefully(0, 100, TimeUnit.MILLISECONDS).sync()
    }

    private fun gate(registry: ConnectionRegistry, rules: RulesEngine? = null, intercept: InterceptController = InterceptController()) =
        MessageGate(registry, intercept, MatchReplaceEngine()) { _, _, _, _ -> }.also { it.rulesEngine = rules }

    private fun tcp(config: ListenerConfig, registry: ConnectionRegistry, g: MessageGate, provider: BurpCertificateProvider? = null): Pair<TcpListener, Int> {
        val l = TcpListener(config, registry, boss, worker, g, provider)
        val port = (l.start().sync().channel().localAddress() as InetSocketAddress).port
        closeables += AutoCloseable { l.stop() }
        return l to port
    }

    private fun trustAll(): SSLContext = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }), null)
    }

    private fun tlsClient(port: Int, sni: String, alpn: List<String>): SSLSocket {
        val s = trustAll().socketFactory.createSocket(Socket("127.0.0.1", port), sni, port, true) as SSLSocket
        if (alpn.isNotEmpty()) s.sslParameters = s.sslParameters.apply { applicationProtocols = alpn.toTypedArray() }
        s.soTimeout = 5000
        closeables += s
        return s
    }

    private fun closedPort(): Int = ServerSocket(0).use { it.localPort }

    // ── H3: ALPN ───────────────────────────────────────────────────────

    /** TLS echo upstream advertising [protocols] via ALPN; records what each handshake selected. */
    private class AlpnTlsEcho(keystore: File, protocols: List<String>) : AutoCloseable {
        private val server: SSLServerSocket
        val selected = CopyOnWriteArrayList<String>()
        val port: Int get() = server.localPort
        init {
            val ks = KeyStore.getInstance("PKCS12").apply { keystore.inputStream().use { load(it, TestCa.password) } }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, TestCa.password) }
            val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
            server = ctx.serverSocketFactory.createServerSocket(0) as SSLServerSocket
            Thread {
                while (true) {
                    val c = try { server.accept() as SSLSocket } catch (_: Exception) { break }
                    Thread {
                        runCatching {
                            c.use { s ->
                                s.sslParameters = s.sslParameters.apply { applicationProtocols = protocols.toTypedArray() }
                                s.startHandshake()
                                selected += (s.applicationProtocol ?: "")
                                val buf = ByteArray(4096)
                                while (true) { val n = s.inputStream.read(buf); if (n < 0) break; s.outputStream.write(buf, 0, n); s.outputStream.flush() }
                            }
                        }
                    }.apply { isDaemon = true }.start()
                }
            }.apply { isDaemon = true }.start()
        }
        override fun close() { runCatching { server.close() } }
    }

    private fun mitmWith(upstreamProtocols: List<String>, rules: RulesEngine? = null, registry: ConnectionRegistry = ConnectionRegistry()): Pair<AlpnTlsEcho, Int> {
        val up = AlpnTlsEcho(TestCa.keystore(tempDir, "upstream.test", ca = false), upstreamProtocols).also { closeables += it }
        val provider = BurpCertificateProvider(TestCa.keystore(tempDir, "CA", ca = true), TestCa.password)
        val (_, port) = tcp(ListenerConfig("alpn", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", up.port, tlsMode = TlsMode.MITM), registry, gate(registry, rules), provider)
        return up to port
    }

    private fun echo(s: SSLSocket, bytes: ByteArray): ByteArray {
        s.outputStream.write(bytes); s.outputStream.flush()
        return s.inputStream.readNBytes(bytes.size)
    }

    private val h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray() + byteArrayOf(0, 0, 0, 4, 0, 0, 0, 0, 0)

    @Test
    fun `without active rules MITM negotiates h2 end to end, relaying the bytes`() {
        val (up, port) = mitmWith(listOf("h2", "http/1.1"), RulesEngine())
        val s = tlsClient(port, "svc.test", listOf("h2", "http/1.1"))
        s.startHandshake()
        assertEquals("h2", s.applicationProtocol)
        assertArrayEquals(h2Preface, echo(s, h2Preface))
        assertEquals(listOf("h2"), up.selected.toList())
    }

    @Test
    fun `with an active rule MITM offers only http1_1 on both legs and the rule runs`() {
        // A non-mock rule (no lazy dial): before the fix h2 was negotiated and the rule silently skipped.
        val rules = RulesEngine().apply {
            add(RuleCodec.fromJson("""{"match":{"path":"/x"},"actions":[{"type":"transformRequest","setHeaders":{"X-Ruled":"1"}}]}"""))
        }
        val (up, port) = mitmWith(listOf("h2", "http/1.1"), rules)
        val s = tlsClient(port, "svc.test", listOf("h2", "http/1.1"))
        s.startHandshake()
        assertEquals("http/1.1", s.applicationProtocol)
        s.outputStream.write("GET /x HTTP/1.1\r\nHost: svc.test\r\n\r\n".toByteArray()); s.outputStream.flush()
        // The upstream is an echo: what comes back is the request as the rules layer forwarded it.
        val back = String(s.inputStream.readNBytes("GET /x HTTP/1.1\r\nHost: svc.test\r\nX-Ruled: 1\r\n\r\n".length))
        assertTrue(back.contains("X-Ruled: 1"), back)
        assertEquals(listOf("http/1.1"), up.selected.toList(), "upstream must only be offered http/1.1")
    }

    @Test
    fun `an h2-only client with an active rule keeps h2 but the bypass is noted in history, never silent`() {
        val rules = RulesEngine().apply { add(RuleCodec.fromJson("""{"match":{"path":"/x"},"actions":[{"type":"delay","ms":1}]}""")) }
        val registry = ConnectionRegistry()
        val (up, port) = mitmWith(listOf("h2", "http/1.1"), rules, registry)
        val s = tlsClient(port, "svc.test", listOf("h2"))
        s.startHandshake()
        assertEquals("h2", s.applicationProtocol)
        assertArrayEquals(h2Preface, echo(s, h2Preface))
        assertEquals(listOf("h2"), up.selected.toList())
        waitUntil { registry.allMessages().any { it.isNote && it.dissectedView!!.startsWith("RULES BYPASSED: HTTP/2") } }
    }

    @Test
    fun `a rule enabled while an h2 connection is live is reported on that connection`() {
        val rules = RulesEngine()
        val registry = ConnectionRegistry()
        val (_, port) = mitmWith(listOf("h2", "http/1.1"), rules, registry)
        val s = tlsClient(port, "svc.test", listOf("h2", "http/1.1"))
        s.startHandshake()
        assertEquals("h2", s.applicationProtocol)
        assertArrayEquals(h2Preface, echo(s, h2Preface))
        assertTrue(registry.allMessages().none { it.isNote && it.dissectedView!!.contains("BYPASSED") }, "no rule yet: no note")
        rules.add(RuleCodec.fromJson("""{"match":{},"actions":[{"type":"delay","ms":1}]}"""))
        val frame = byteArrayOf(0, 0, 0, 4, 1, 0, 0, 0, 0)
        assertArrayEquals(frame, echo(s, frame))
        waitUntil { registry.allMessages().any { it.isNote && it.dissectedView!!.startsWith("RULES BYPASSED: HTTP/2") } }
        // A NEW connection now gets http/1.1.
        val s2 = tlsClient(port, "svc.test", listOf("h2", "http/1.1"))
        s2.startHandshake()
        assertEquals("http/1.1", s2.applicationProtocol)
    }

    @Test
    fun `MITM selects http1_1 when the upstream does not speak h2`() {
        val (up, port) = mitmWith(listOf("http/1.1"))
        val s = tlsClient(port, "svc.test", listOf("h2", "http/1.1"))
        s.startHandshake()
        assertEquals("http/1.1", s.applicationProtocol)
        assertArrayEquals("ping".toByteArray(), echo(s, "ping".toByteArray()))
        assertEquals(listOf("http/1.1"), up.selected.toList())
    }

    @Test
    fun `client without ALPN still works and the upstream is offered none`() {
        val (up, port) = mitmWith(listOf("h2", "http/1.1"))
        val s = tlsClient(port, "svc.test", emptyList())
        s.startHandshake()
        assertTrue(s.applicationProtocol.isNullOrEmpty())
        assertArrayEquals("x".toByteArray(), echo(s, "x".toByteArray()))
        assertEquals(listOf(""), up.selected.toList())
    }

    @Test
    fun `MITM connections (TCP and SOCKS5) are marked TLS in the registry, passthrough ones are not`() {
        val up = AlpnTlsEcho(TestCa.keystore(tempDir, "upstream.test", ca = false), emptyList()).also { closeables += it }
        val provider = BurpCertificateProvider(TestCa.keystore(tempDir, "CA", ca = true), TestCa.password)
        val registry = ConnectionRegistry()
        val (_, port) = tcp(ListenerConfig("tls", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", up.port, tlsMode = TlsMode.MITM,
            tlsPassthrough = listOf("raw.test")), registry, gate(registry), provider)

        assertArrayEquals("m".toByteArray(), echo(tlsClient(port, "mitm.test", emptyList()), "m".toByteArray()))
        waitUntil { registry.connection(1)?.tls == true }
        assertArrayEquals("p".toByteArray(), echo(tlsClient(port, "raw.test", emptyList()), "p".toByteArray()))
        Thread.sleep(200)
        assertEquals(false, registry.connection(2)?.tls)

        val socks = Socks5Listener(Socks5ListenerConfig("stls", "127.0.0.1", 0, tlsMode = TlsMode.MITM), registry, boss, worker, gate(registry), provider)
        val sp = (socks.start().sync().channel().localAddress() as InetSocketAddress).port
        closeables += AutoCloseable { socks.stop() }
        val plain = Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", sp))).also { closeables += it }
        plain.connect(InetSocketAddress("127.0.0.1", up.port))
        val s = (trustAll().socketFactory.createSocket(plain, "svc.socks.test", up.port, true) as SSLSocket).also { it.soTimeout = 5000; closeables += it }
        assertArrayEquals("s".toByteArray(), echo(s, "s".toByteArray()))
        waitUntil { registry.connection(3)?.tls == true }
    }

    @Test
    fun `ALPN list is parsed from a real ClientHello`() {
        val engine = SSLContext.getInstance("TLS").apply { init(null, null, null) }.createSSLEngine("a.test", 443)
        engine.useClientMode = true
        engine.sslParameters = engine.sslParameters.apply { applicationProtocols = arrayOf("h2", "http/1.1") }
        val out = ByteBuffer.allocate(engine.session.packetBufferSize)
        engine.wrap(ByteBuffer.allocate(0), out)
        out.flip()
        val record = ByteArray(out.remaining()).also { out.get(it) }
        val body = Unpooled.wrappedBuffer(record, 9, record.size - 9) // skip record (5) + handshake (4) headers
        assertEquals(listOf("h2", "http/1.1"), SniTlsRouter.parseAlpn(body))
        assertEquals(emptyList<String>(), SniTlsRouter.parseAlpn(Unpooled.wrappedBuffer(ByteArray(10))))
    }

    // ── M3: upstream socket leak ───────────────────────────────────────

    @Test
    fun `an upstream that connects after the client left is closed, not leaked`() {
        ServerSocket(0).use { server ->
            val registry = ConnectionRegistry()
            val config = ListenerConfig("leak", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", server.localPort)
            val conn = TcpConnection(1, config, EmbeddedChannel(), gate(registry))
            conn.close()                                   // client gone before the dial finished
            conn.connectUpstream(worker) { }
            server.soTimeout = 5000
            server.accept().use { s ->
                s.soTimeout = 5000
                assertEquals(-1, s.getInputStream().read(), "upstream socket must be closed by the proxy")
            }
        }
    }

    // ── M5: SNI flood ──────────────────────────────────────────────────

    @Test
    fun `leaves share one key pair, so minting many SNIs is cheap`() {
        val provider = BurpCertificateProvider(TestCa.keystore(tempDir, "CA", ca = true), TestCa.password, maxCachedLeaves = 64)
        val a = provider.leafCertificateFor("a.test")
        val b = provider.leafCertificateFor("b.test")
        assertSame(a.second, b.second)
        assertNotEquals(a.first, b.first)
        val t0 = System.nanoTime()
        repeat(200) { provider.leafCertificateFor("h$it.flood.test") }
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertTrue(ms < 10_000, "200 leaves took ${ms}ms")
        assertSame(provider.serverContext(listOf("c.test")), provider.serverContext(listOf("c.test")))
        assertNotSame(provider.serverContext(listOf("c.test")), provider.serverContext(listOf("c.test"), "h2"))
    }

    @Test
    fun `random-SNI flood does not stall other connections on the shared event loops`() {
        TcpEchoServer().use { plainUp ->
            val (up, mitmPort) = mitmWith(listOf("http/1.1"))
            val registry = ConnectionRegistry()
            val (_, plainPort) = tcp(ListenerConfig("plain", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", plainUp.port), registry, gate(registry))
            val pool = Executors.newFixedThreadPool(16)
            try {
                val futures = (0 until 48).map { i ->
                    pool.submit { runCatching { tlsClient(mitmPort, "r$i-${System.nanoTime()}.flood.test", emptyList()).startHandshake() } }
                }
                // While the flood is in progress a plain relay on the same worker group stays responsive.
                Socket("127.0.0.1", plainPort).use { c ->
                    c.soTimeout = 2000
                    val t0 = System.nanoTime()
                    c.getOutputStream().write("hello".toByteArray())
                    assertEquals("hello", String(c.getInputStream().readNBytes(5)))
                    assertTrue((System.nanoTime() - t0) / 1_000_000 < 2000)
                }
                futures.forEach { it.get(30, TimeUnit.SECONDS) }
                // And the MITM listener still serves a fresh client afterwards.
                val s = tlsClient(mitmPort, "after.flood.test", emptyList())
                assertArrayEquals("ok".toByteArray(), echo(s, "ok".toByteArray()))
            } finally {
                pool.shutdownNow()
            }
            assertTrue(up.selected.isNotEmpty())
        }
    }

    // ── M6: UDP session cap ────────────────────────────────────────────

    @Test
    fun `UDP sessions respect the registry's open-connection limit`() {
        DatagramSocket(0).use { echo ->
            Thread {
                val buf = ByteArray(1500)
                while (!echo.isClosed) {
                    val p = DatagramPacket(buf, buf.size)
                    runCatching { echo.receive(p); echo.send(DatagramPacket(p.data, p.length, p.socketAddress)) }
                }
            }.apply { isDaemon = true }.start()
            val registry = ConnectionRegistry(maxOpenConnections = 2)
            val l = UdpListener(ListenerConfig("udp", Protocol.UDP, "127.0.0.1", 0, "127.0.0.1", echo.localPort), registry, worker, gate(registry))
            val port = (l.start().sync().channel().localAddress() as InetSocketAddress).port
            try {
                val clients = (0 until 3).map { DatagramSocket().also { s -> s.soTimeout = 1500; closeables += s } }
                val answered = clients.map { c ->
                    c.send(DatagramPacket("hi".toByteArray(), 2, InetSocketAddress("127.0.0.1", port)))
                    try { c.receive(DatagramPacket(ByteArray(16), 16)); true } catch (_: SocketTimeoutException) { false }
                }
                assertEquals(listOf(true, true, false), answered)
                assertEquals(2, registry.openConnectionCount())
            } finally { l.stop() }
            assertEquals(0, registry.openConnectionCount())
        }
    }

    // ── M7: stop closes live connections ───────────────────────────────

    @Test
    fun `stopping a TCP or SOCKS5 listener closes its open connections`() {
        TcpEchoServer().use { up ->
            val registry = ConnectionRegistry()
            val (tcpListener, port) = tcp(ListenerConfig("t", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", up.port), registry, gate(registry))
            val c = Socket("127.0.0.1", port).also { it.soTimeout = 3000; closeables += it }
            c.getOutputStream().write("a".toByteArray())
            assertEquals("a", String(c.getInputStream().readNBytes(1)))
            tcpListener.stop()
            assertEquals(-1, c.getInputStream().read())
            waitUntil { registry.openConnectionCount() == 0 }

            val socks = Socks5Listener(Socks5ListenerConfig("s", "127.0.0.1", 0), registry, boss, worker, gate(registry))
            val sp = (socks.start().sync().channel().localAddress() as InetSocketAddress).port
            val sc = Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", sp))).also { it.soTimeout = 3000; closeables += it }
            sc.connect(InetSocketAddress("127.0.0.1", up.port))
            sc.getOutputStream().write("b".toByteArray())
            assertEquals("b", String(sc.getInputStream().readNBytes(1)))
            socks.stop()
            assertEquals(-1, sc.getInputStream().read())
            waitUntil { registry.openConnectionCount() == 0 }
        }
    }

    // ── Mock without a live upstream (lazy dial) ───────────────────────

    private val mockRule = """{"match":{"path":"/mock*"},"actions":[{"type":"mock","status":418,"body":"teapot"}]}"""
    private fun get(path: String) = "GET $path HTTP/1.1\r\nHost: app.test\r\n\r\n".toByteArray()

    @Test
    fun `fixed listener with a mock rule serves mocks for a dead upstream and 502s the rest`() {
        val rules = RulesEngine().apply { add(RuleCodec.fromJson(mockRule)) }
        val registry = ConnectionRegistry()
        val (_, port) = tcp(ListenerConfig("m", Protocol.TCP, "127.0.0.1", 0, "does-not-exist.invalid", 80), registry, gate(registry, rules))
        val c = Socket("127.0.0.1", port).also { it.soTimeout = 10_000; closeables += it }
        c.getOutputStream().write(get("/mock/a"))
        assertEquals(418, Wire.read(c.getInputStream())!!.status)
        c.getOutputStream().write(get("/mock/b"))                     // keep-alive still works
        assertEquals("teapot", Wire.read(c.getInputStream())!!.body)
        c.getOutputStream().write(get("/real"))
        val r = Wire.read(c.getInputStream())!!
        assertEquals(502, r.status)
        assertTrue("does-not-exist.invalid" in r.body, r.body)
    }

    @Test
    fun `SOCKS5 with a mock rule accepts a CONNECT to a nonexistent host and mocks it`() {
        val rules = RulesEngine().apply { add(RuleCodec.fromJson(mockRule)) }
        val registry = ConnectionRegistry()
        val socks = Socks5Listener(Socks5ListenerConfig("sm", "127.0.0.1", 0), registry, boss, worker, gate(registry, rules))
        val sp = (socks.start().sync().channel().localAddress() as InetSocketAddress).port
        closeables += AutoCloseable { socks.stop() }
        val c = Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", sp))).also { it.soTimeout = 10_000; closeables += it }
        c.connect(InetSocketAddress.createUnresolved("nohost.invalid", 80))
        c.getOutputStream().write(get("/mock"))
        assertEquals(418, Wire.read(c.getInputStream())!!.status)
        c.getOutputStream().write(get("/real"))
        assertEquals(502, Wire.read(c.getInputStream())!!.status)
    }

    @Test
    fun `lazy dial still reaches a live upstream, and a silent client still gets the server banner`() {
        val rules = RulesEngine().apply { add(RuleCodec.fromJson(mockRule)) }
        expedition.rules.FakeHttpServer("A").use { up ->
            val registry = ConnectionRegistry()
            val (_, port) = tcp(ListenerConfig("m2", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", up.port), registry, gate(registry, rules))
            val c = Socket("127.0.0.1", port).also { it.soTimeout = 5000; closeables += it }
            c.getOutputStream().write(get("/mock"))
            assertEquals(418, Wire.read(c.getInputStream())!!.status)
            assertEquals(0, up.accepted.get())
            c.getOutputStream().write(get("/real"))
            assertEquals("A:GET /real body=", Wire.read(c.getInputStream())!!.body)
        }
        ServerSocket(0).use { banner ->
            Thread { runCatching { banner.accept().use { it.getOutputStream().write("220 hi\r\n".toByteArray()); Thread.sleep(2000) } } }
                .apply { isDaemon = true }.start()
            val registry = ConnectionRegistry()
            val (_, port) = tcp(ListenerConfig("smtp", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", banner.localPort), registry, gate(registry, rules))
            val c = Socket("127.0.0.1", port).also { it.soTimeout = 5000; closeables += it }
            assertEquals("220 hi\r\n", String(c.getInputStream().readNBytes(8)))
        }
    }

    @Test
    fun `without a mock rule a dead SOCKS destination still fails the handshake`() {
        val registry = ConnectionRegistry()
        val socks = Socks5Listener(Socks5ListenerConfig("sd", "127.0.0.1", 0), registry, boss, worker, gate(registry, RulesEngine()))
        val sp = (socks.start().sync().channel().localAddress() as InetSocketAddress).port
        closeables += AutoCloseable { socks.stop() }
        val c = Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", sp))).also { it.soTimeout = 5000; closeables += it }
        assertThrows(java.io.IOException::class.java) { c.connect(InetSocketAddress("127.0.0.1", closedPort())) }
    }

    // ── L1: held messages of a closed connection ───────────────────────

    @Test
    fun `held messages are discarded when their connection closes`() {
        val intercept = InterceptController().apply { setEnabled(true) }
        val decision = AtomicReference<InterceptDecision>()
        intercept.submit(StreamKey(7, "CLIENT_TO_UPSTREAM"), 7, "CLIENT_TO_UPSTREAM", "x".toByteArray(), { _, _ -> }) { decision.set(it) }
        intercept.submit(StreamKey(8, "CLIENT_TO_UPSTREAM"), 8, "CLIENT_TO_UPSTREAM", "y".toByteArray(), { _, _ -> }) { }
        assertEquals(2, intercept.heldMessages().size)
        intercept.discardConnection(7)
        assertEquals(listOf(8L), intercept.heldMessages().map { it.connectionId })
        assertEquals(InterceptDecision.Drop, decision.get())

        // Through the engine: closing the connection empties the held list.
        TcpEchoServer().use { up ->
            val registry = ConnectionRegistry()
            val ic = InterceptController().apply { setEnabled(true) }
            val (_, port) = tcp(ListenerConfig("h", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", up.port), registry, gate(registry, intercept = ic))
            Socket("127.0.0.1", port).use { c ->
                c.getOutputStream().write("held".toByteArray()); c.getOutputStream().flush()
                waitUntil { ic.heldMessages().isNotEmpty() }
            }
            waitUntil { ic.heldMessages().isEmpty() }
        }
    }
}
