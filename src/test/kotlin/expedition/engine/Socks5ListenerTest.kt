package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket

class Socks5ListenerTest {

    private fun startedPort(l: Socks5Listener) =
        (l.start().sync().channel().localAddress() as InetSocketAddress).port

    private fun readN(socket: Socket, n: Int): ByteArray {
        val buf = ByteArray(n); var total = 0
        while (total < n) {
            val r = socket.getInputStream().read(buf, total, n - total)
            if (r < 0) break; total += r
        }
        return buf
    }

    @Test
    fun `relays through SOCKS5 to the negotiated destination and records it`() {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        TcpEchoServer().use { echo ->
            val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
            val listener = Socks5Listener(Socks5ListenerConfig("socks", "127.0.0.1", 0), registry, boss, worker, gate)
            try {
                val port = startedPort(listener)
                val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
                Socket(proxy).use { client ->
                    client.connect(InetSocketAddress("127.0.0.1", echo.port))
                    client.getOutputStream().write("ping".toByteArray()); client.getOutputStream().flush()
                    assertEquals("ping", String(readN(client, 4)))
                }
                waitUntil { registry.allMessages().size >= 2 }
                assertTrue(registry.allMessages().any { it.direction == Direction.CLIENT_TO_UPSTREAM })
                assertTrue(registry.allMessages().any { it.direction == Direction.UPSTREAM_TO_CLIENT })
            } finally {
                listener.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
            }
        }
    }

    @Test
    fun `applies match and replace on the SOCKS5 relay`() {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val mr = MatchReplaceEngine().apply { addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar")) }
        TcpEchoServer().use { echo ->
            val gate = MessageGate(registry, InterceptController(), mr) { _, _, _, _ -> }
            val listener = Socks5Listener(Socks5ListenerConfig("socks2", "127.0.0.1", 0), registry, boss, worker, gate)
            try {
                val port = startedPort(listener)
                val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
                Socket(proxy).use { client ->
                    client.connect(InetSocketAddress("127.0.0.1", echo.port))
                    client.getOutputStream().write("foo".toByteArray()); client.getOutputStream().flush()
                    assertEquals("bar", String(readN(client, 3)))
                }
            } finally {
                listener.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
            }
        }
    }
}

/** Raw-byte SOCKS5 tests: reply codes on connect failure, RFC 1929 auth, and SOCKS5 + TLS MITM. */
class Socks5ListenerProtocolTest {

    @org.junit.jupiter.api.io.TempDir lateinit var tempDir: java.io.File

    private fun readN(input: java.io.InputStream, n: Int): ByteArray {
        val buf = ByteArray(n); var total = 0
        while (total < n) { val r = input.read(buf, total, n - total); if (r < 0) break; total += r }
        return buf.copyOf(total)
    }

    private fun connectRequest(port: Int): ByteArray =
        byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, (port shr 8).toByte(), port.toByte())

    private fun <T> withSocks(config: Socks5ListenerConfig, provider: expedition.tls.BurpCertificateProvider? = null, body: (Int) -> T): T {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
        val listener = Socks5Listener(config, registry, boss, worker, gate, provider)
        try {
            val port = (listener.start().sync().channel().localAddress() as InetSocketAddress).port
            return body(port)
        } finally {
            listener.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
        }
    }

    @Test
    fun `connect to a closed port replies connection refused and closes`() {
        val closedPort = java.net.ServerSocket(0).use { it.localPort }
        withSocks(Socks5ListenerConfig("s-refused", "127.0.0.1", 0)) { port ->
            Socket("127.0.0.1", port).use { s ->
                s.soTimeout = 5000
                s.getOutputStream().write(byteArrayOf(5, 1, 0)); s.getOutputStream().flush()
                assertArrayEquals(byteArrayOf(5, 0), readN(s.getInputStream(), 2))
                s.getOutputStream().write(connectRequest(closedPort)); s.getOutputStream().flush()
                val reply = readN(s.getInputStream(), 2)
                assertEquals(5, reply[0].toInt())
                assertEquals(0x05, reply[1].toInt(), "expected 0x05 connection refused")
                // Rest of the reply, then EOF: the listener closed the connection.
                readN(s.getInputStream(), 8)
                assertEquals(-1, s.getInputStream().read())
            }
        }
    }

    @Test
    fun `connect failures map to the right SOCKS5 reply codes`() {
        assertEquals(0x04, Socks5Listener.socksStatusFor(java.net.UnknownHostException("nope.invalid")).byteValue().toInt())
        assertEquals(0x04, Socks5Listener.socksStatusFor(io.netty.channel.ConnectTimeoutException("timed out")).byteValue().toInt())
        assertEquals(0x04, Socks5Listener.socksStatusFor(java.net.NoRouteToHostException("no route")).byteValue().toInt())
        assertEquals(0x05, Socks5Listener.socksStatusFor(java.net.ConnectException("Connection refused")).byteValue().toInt())
        assertEquals(0x01, Socks5Listener.socksStatusFor(io.netty.handler.proxy.ProxyConnectException("proxy said no")).byteValue().toInt())
        assertEquals(0x01, Socks5Listener.socksStatusFor(RuntimeException("boom")).byteValue().toInt())
    }

    @Test
    fun `username and password auth - correct credentials relay`() {
        TcpEchoServer().use { echo ->
            withSocks(Socks5ListenerConfig("s-auth", "127.0.0.1", 0, username = "user", password = "pa55")) { port ->
                Socket("127.0.0.1", port).use { s ->
                    s.soTimeout = 5000
                    val out = s.getOutputStream(); val input = s.getInputStream()
                    out.write(byteArrayOf(5, 2, 0, 2)); out.flush()
                    assertArrayEquals(byteArrayOf(5, 2), readN(input, 2))
                    out.write(byteArrayOf(1, 4) + "user".toByteArray() + byteArrayOf(4) + "pa55".toByteArray()); out.flush()
                    assertArrayEquals(byteArrayOf(1, 0), readN(input, 2))
                    out.write(connectRequest(echo.port)); out.flush()
                    val reply = readN(input, 10)
                    assertEquals(0, reply[1].toInt())
                    out.write("ping".toByteArray()); out.flush()
                    assertEquals("ping", String(readN(input, 4)))
                }
            }
        }
    }

    @Test
    fun `username and password auth - wrong password is rejected and closed`() {
        withSocks(Socks5ListenerConfig("s-auth2", "127.0.0.1", 0, username = "user", password = "pa55")) { port ->
            Socket("127.0.0.1", port).use { s ->
                s.soTimeout = 5000
                val out = s.getOutputStream(); val input = s.getInputStream()
                out.write(byteArrayOf(5, 1, 2)); out.flush()
                assertArrayEquals(byteArrayOf(5, 2), readN(input, 2))
                out.write(byteArrayOf(1, 4) + "user".toByteArray() + byteArrayOf(5) + "wrong".toByteArray()); out.flush()
                val r = readN(input, 2)
                assertEquals(1, r[0].toInt())
                assertNotEquals(0, r[1].toInt(), "RFC 1929: any non-zero status is a failure")
                assertEquals(-1, input.read())
            }
        }
    }

    @Test
    fun `auth-required listener refuses a client offering only no-auth`() {
        withSocks(Socks5ListenerConfig("s-auth3", "127.0.0.1", 0, username = "user", password = "pa55")) { port ->
            Socket("127.0.0.1", port).use { s ->
                s.soTimeout = 5000
                s.getOutputStream().write(byteArrayOf(5, 1, 0)); s.getOutputStream().flush()
                assertArrayEquals(byteArrayOf(5, 0xFF.toByte()), readN(s.getInputStream(), 2))
                assertEquals(-1, s.getInputStream().read())
            }
        }
    }

    @Test
    fun `SOCKS5 with TLS MITM presents an SNI-specific leaf and decrypts`() {
        val provider = expedition.tls.BurpCertificateProvider(TestCa.keystore(tempDir, "Test CA", ca = true), TestCa.password)
        SniRecordingTlsEchoServer(TestCa.keystore(tempDir, "upstream.test", ca = false), TestCa.password).use { upstream ->
            withSocks(Socks5ListenerConfig("s-mitm", "127.0.0.1", 0, tlsMode = TlsMode.MITM), provider) { port ->
                val plain = Socket(java.net.Proxy(java.net.Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
                plain.connect(InetSocketAddress("127.0.0.1", upstream.port))
                val ts = java.security.KeyStore.getInstance("PKCS12").apply { load(null, null); setCertificateEntry("ca", provider.caCertificate) }
                val tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()).apply { init(ts) }
                val ctx = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
                (ctx.socketFactory.createSocket(plain, "svc.socks.test", upstream.port, true) as javax.net.ssl.SSLSocket).use { s ->
                    s.sslParameters = s.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    s.soTimeout = 5000
                    s.startHandshake()
                    val leaf = s.session.peerCertificates[0] as java.security.cert.X509Certificate
                    assertEquals(provider.caCertificate.subjectX500Principal, leaf.issuerX500Principal)
                    s.outputStream.write("tls".toByteArray()); s.outputStream.flush()
                    assertEquals("tls", String(readN(s.inputStream, 3)))
                }
                waitUntil { "svc.socks.test" in upstream.sniSeen }
            }
        }
    }

    @Test
    fun `SOCKS5 MITM listener without a certificate provider fails at start`() {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        try {
            val l = Socks5Listener(Socks5ListenerConfig("s-nocert", "127.0.0.1", 0, tlsMode = TlsMode.MITM), ConnectionRegistry(), boss, worker)
            assertThrows(IllegalStateException::class.java) { l.start() }
        } finally { boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync() }
    }
}
