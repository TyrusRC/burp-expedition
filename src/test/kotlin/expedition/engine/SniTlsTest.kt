package expedition.engine

import expedition.engine.tls.SniTlsRouter
import expedition.engine.tls.TlsDecision
import expedition.engine.tls.TlsPassthroughMatcher
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import expedition.tls.BurpCertificateProvider
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.*

/** Per-connection leaf selection from the ClientHello's SNI, and SNI-based TLS passthrough. */
class SniTlsTest {

    @TempDir lateinit var tempDir: File
    private lateinit var boss: NioEventLoopGroup
    private lateinit var worker: NioEventLoopGroup
    private lateinit var provider: BurpCertificateProvider
    private lateinit var upstream: SniRecordingTlsEchoServer

    @BeforeEach
    fun setUp() {
        boss = NioEventLoopGroup(1); worker = NioEventLoopGroup()
        provider = BurpCertificateProvider(TestCa.keystore(tempDir, "Test Expedition CA", ca = true), TestCa.password)
        upstream = SniRecordingTlsEchoServer(TestCa.keystore(tempDir, "upstream.test", ca = false), TestCa.password)
    }

    @AfterEach
    fun tearDown() {
        upstream.close()
        boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
    }

    private fun caTrustingContext(): SSLContext {
        val ts = KeyStore.getInstance("PKCS12").apply { load(null, null); setCertificateEntry("ca", this@SniTlsTest.provider.caCertificate) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ts) }
        return SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
    }

    private fun trustAllContext(): SSLContext = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }), null)
    }

    /** TLS over a plain socket to 127.0.0.1:[port], sending SNI [sni] (null = connect by IP, no SNI). */
    private fun handshake(ctx: SSLContext, port: Int, sni: String?, verifyHostname: Boolean): Pair<X509Certificate, SSLSocket> {
        val plain = Socket("127.0.0.1", port)
        val s = ctx.socketFactory.createSocket(plain, sni ?: "127.0.0.1", port, true) as SSLSocket
        if (verifyHostname) s.sslParameters = s.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
        s.soTimeout = 5000
        s.startHandshake()
        return (s.session.peerCertificates[0] as X509Certificate) to s
    }

    private fun echo(s: SSLSocket, text: String): String {
        s.outputStream.write(text.toByteArray()); s.outputStream.flush()
        val buf = ByteArray(text.length); var total = 0
        while (total < buf.size) { val r = s.inputStream.read(buf, total, buf.size - total); if (r < 0) break; total += r }
        return String(buf, 0, total)
    }

    private fun sans(cert: X509Certificate): Set<Pair<Int, String>> =
        cert.subjectAlternativeNames.map { (it[0] as Int) to (it[1] as String) }.toSet()

    private fun <T> withListener(config: ListenerConfig, registry: ConnectionRegistry = ConnectionRegistry(), body: (Int) -> T): T {
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
        val listener = TcpListener(config, registry, boss, worker, gate, provider)
        try {
            val port = (listener.start().sync().channel().localAddress() as InetSocketAddress).port
            return body(port)
        } finally { listener.stop() }
    }

    @Test
    fun `different SNI values get different leaves, each valid for its own name`() {
        val config = ListenerConfig("sni", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", upstream.port, TlsMode.MITM)
        withListener(config) { port ->
            val (a, sa) = handshake(caTrustingContext(), port, "a.example.test", verifyHostname = true)
            sa.use { assertEquals("hi", echo(it, "hi")) }
            val (b, sb) = handshake(caTrustingContext(), port, "b.example.test", verifyHostname = true)
            sb.use { assertEquals("yo", echo(it, "yo")) }

            assertNotEquals(a.serialNumber, b.serialNumber)
            assertEquals(provider.caCertificate.subjectX500Principal, a.issuerX500Principal)
            // DNS SAN for the SNI + IP SAN for the listener's (IP) upstream host.
            assertTrue((2 to "a.example.test") in sans(a), sans(a).toString())
            assertTrue((7 to "127.0.0.1") in sans(a), sans(a).toString())
            assertTrue((2 to "b.example.test") in sans(b), sans(b).toString())
            assertFalse((2 to "a.example.test") in sans(b))
            // The proxy forwards the client's SNI to the upstream.
            waitUntil { upstream.sniSeen.containsAll(listOf("a.example.test", "b.example.test")) }
        }
    }

    @Test
    fun `no SNI falls back to the listener upstream host`() {
        val config = ListenerConfig("nosni", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", upstream.port, TlsMode.MITM)
        withListener(config) { port ->
            val (leaf, s) = handshake(caTrustingContext(), port, null, verifyHostname = true)
            s.use { assertEquals("ok", echo(it, "ok")) }
            assertEquals(setOf(7 to "127.0.0.1"), sans(leaf))
        }
    }

    @Test
    fun `invalid or missing SNI decides MITM on the fallback host`() {
        val none = TlsPassthroughMatcher(emptyList())
        assertEquals(TlsDecision.Mitm(null, listOf("upstream.test")), SniTlsRouter.decide(null, "upstream.test", none))
        assertEquals(TlsDecision.Mitm(null, listOf("upstream.test")), SniTlsRouter.decide("bad,cn=evil", "upstream.test", none))
        assertEquals(TlsDecision.Mitm(null, listOf("upstream.test")), SniTlsRouter.decide("a b.test", "upstream.test", none))
        assertEquals(TlsDecision.Mitm("x.test", listOf("x.test", "upstream.test")), SniTlsRouter.decide("X.Test.", "upstream.test", none))
    }

    @Test
    fun `passthrough pattern matching`() {
        val m = TlsPassthroughMatcher(listOf("exact.test", "*.wild.test"))
        assertTrue(m.matches("exact.test"))
        assertTrue(m.matches("EXACT.test."))
        assertFalse(m.matches("sub.exact.test"))
        assertTrue(m.matches("a.wild.test"))
        assertTrue(m.matches("a.b.wild.test"))
        assertFalse(m.matches("wild.test"))
        assertFalse(m.matches("notwild.test"))
        assertFalse(m.matches(null))
        assertThrows(IllegalArgumentException::class.java) { TlsPassthroughMatcher(listOf("*")) }
        assertThrows(IllegalArgumentException::class.java) { TlsPassthroughMatcher(listOf("a,b")) }
    }

    @Test
    fun `matching SNI is relayed raw - the client sees the upstream's own certificate`() {
        val registry = ConnectionRegistry()
        val config = ListenerConfig("pt", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", upstream.port, TlsMode.MITM,
            tlsPassthrough = listOf("*.pass.test"))
        withListener(config, registry) { port ->
            val (leaf, s) = handshake(trustAllContext(), port, "api.pass.test", verifyHostname = false)
            s.use { assertEquals("raw!", echo(it, "raw!")) }
            // Not re-signed: the upstream's self-signed cert reached the client untouched.
            assertEquals("CN=upstream.test", leaf.subjectX500Principal.name)
            assertEquals("CN=upstream.test", leaf.issuerX500Principal.name)
            // The upstream saw the client's original ClientHello (its SNI).
            waitUntil { "api.pass.test" in upstream.sniSeen }
            // History marks the connection as passthrough; no decrypted plaintext was recorded.
            waitUntil { registry.allMessages().any { it.dissectedView?.contains("TLS PASSTHROUGH") == true } }
            assertTrue(registry.allMessages().none { String(it.rawBytes).contains("raw!") })
        }
    }

    @Test
    fun `non-matching SNI on a passthrough listener is still MITMed`() {
        val registry = ConnectionRegistry()
        val config = ListenerConfig("pt2", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", upstream.port, TlsMode.MITM,
            tlsPassthrough = listOf("*.pass.test"))
        withListener(config, registry) { port ->
            val (leaf, s) = handshake(trustAllContext(), port, "other.test", verifyHostname = false)
            s.use { assertEquals("dec", echo(it, "dec")) }
            assertEquals(provider.caCertificate.subjectX500Principal, leaf.issuerX500Principal)
            waitUntil { registry.allMessages().any { String(it.rawBytes) == "dec" } }
        }
    }

    @Test
    fun `MITM listener without a certificate provider fails at start`() {
        val config = ListenerConfig("nocert", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", 1, TlsMode.MITM)
        val listener = TcpListener(config, ConnectionRegistry(), boss, worker)
        val e = assertThrows(IllegalStateException::class.java) { listener.start() }
        assertTrue(e.message!!.contains("nocert"))
    }
}

/** TLS echo server that records the SNI names its clients requested. */
class SniRecordingTlsEchoServer(keystoreFile: File, password: CharArray) : AutoCloseable {
    private val serverSocket: SSLServerSocket
    val port: Int get() = serverSocket.localPort
    val sniSeen = CopyOnWriteArrayList<String>()

    init {
        val ks = KeyStore.getInstance("PKCS12")
        keystoreFile.inputStream().use { ks.load(it, password) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, password) }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        serverSocket = ctx.serverSocketFactory.createServerSocket(0) as SSLServerSocket
        Thread {
            while (true) {
                val client = try { serverSocket.accept() as SSLSocket } catch (e: Exception) { break }
                Thread {
                    try {
                        client.use { s ->
                            s.startHandshake()
                            (s.session as? ExtendedSSLSession)?.requestedServerNames
                                ?.filterIsInstance<SNIHostName>()?.forEach { sniSeen.add(it.asciiName) }
                            val buf = ByteArray(4096)
                            while (true) {
                                val r = s.inputStream.read(buf); if (r < 0) break
                                s.outputStream.write(buf, 0, r); s.outputStream.flush()
                            }
                        }
                    } catch (_: Exception) { }
                }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true; start() }
    }

    override fun close() { serverSocket.close() }
}
