package expedition.server

import expedition.engine.ProxyEngine
import expedition.engine.TcpEchoServer
import expedition.engine.waitUntil
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * End-to-end: the Control API in front of a REAL ProxyEngine. Confirms the wiring added for
 * SOCKS5 / upstream-proxy / STARTTLS actually starts working listeners and relays traffic —
 * the path Praetor (or curl) drives.
 */
class ControlApiEndToEndTest {

    private lateinit var engine: ProxyEngine
    private lateinit var server: ControlApiServer
    private lateinit var registry: ConnectionRegistry
    private var apiPort = 0
    private val http = HttpClient.newHttpClient()

    private fun freePort() = ServerSocket(0).use { it.localPort }

    @BeforeEach
    fun setUp() {
        registry = ConnectionRegistry()
        engine = ProxyEngine(
            registry, InterceptController(), MatchReplaceEngine(),
            certificateProviderSupplier = { null }, onHeldMessage = { _, _, _, _ -> }, onError = { _, _ -> }
        )
        apiPort = freePort()
        server = ControlApiServer(
            host = "127.0.0.1", port = apiPort,
            registry = registry, matchReplace = MatchReplaceEngine(), intercept = InterceptController(),
            startListener = { engine.startListenerChecked(it) },
            stopListener = { engine.stopListener(it) },
            runningListeners = { engine.runningListenerNames() },
            startSocks5Listener = { engine.startSocks5ListenerChecked(it) },
        )
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.stop()
        engine.shutdown()
    }

    private fun post(path: String, body: String): HttpResponse<String> =
        http.send(
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:$apiPort$path"))
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString()
        )

    private fun get(path: String) =
        http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:$apiPort$path")).build(),
            HttpResponse.BodyHandlers.ofString())

    private fun relay(socket: Socket, payload: String, replyLen: Int): String {
        socket.getOutputStream().write(payload.toByteArray()); socket.getOutputStream().flush()
        val buf = ByteArray(replyLen); var total = 0
        while (total < replyLen) { val r = socket.getInputStream().read(buf, total, replyLen - total); if (r < 0) break; total += r }
        return String(buf)
    }

    @Test
    fun `creates a TCP listener via the API and relays through it`() {
        TcpEchoServer().use { echo ->
            val port = freePort()
            val r = post("/listeners",
                """{"name":"tcp1","protocol":"tcp","bind_host":"127.0.0.1","bind_port":$port,"upstream_host":"127.0.0.1","upstream_port":${echo.port}}""")
            assertEquals(200, r.statusCode(), r.body())
            Socket("127.0.0.1", port).use { assertEquals("ping", relay(it, "ping", 4)) }
            waitUntil { registry.allConnections().isNotEmpty() }
            assertTrue(get("/connections").body().contains("tcp1"))
        }
    }

    @Test
    fun `creates a SOCKS5 listener via the API and relays through it`() {
        TcpEchoServer().use { echo ->
            val port = freePort()
            val r = post("/listeners", """{"name":"socks1","protocol":"socks5","bind_port":$port}""")
            assertEquals(200, r.statusCode(), r.body())
            assertTrue(get("/status").body().contains("socks1"))
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
            Socket(proxy).use { c ->
                c.connect(InetSocketAddress("127.0.0.1", echo.port))
                assertEquals("ping", relay(c, "ping", 4))
            }
        }
    }

    @Test
    fun `chains a listener through an upstream SOCKS5 proxy via the API`() {
        TcpEchoServer().use { echo ->
            val socksPort = freePort()
            assertEquals(200, post("/listeners", """{"name":"outproxy","protocol":"socks5","bind_port":$socksPort}""").statusCode())
            val port = freePort()
            val r = post("/listeners",
                """{"name":"chain","protocol":"tcp","bind_port":$port,"upstream_host":"127.0.0.1","upstream_port":${echo.port},"upstream_proxy":"127.0.0.1:$socksPort"}""")
            assertEquals(200, r.statusCode(), r.body())
            Socket("127.0.0.1", port).use { assertEquals("ping", relay(it, "ping", 4)) }
        }
    }

    @Test
    fun `a bind failure returns an error, not a false 200`() {
        ServerSocket(0).use { reserved ->
            val r = post("/listeners",
                """{"name":"badbind","protocol":"tcp","bind_port":${reserved.localPort},"upstream_host":"127.0.0.1","upstream_port":9}""")
            assertNotEquals(200, r.statusCode(), r.body())
            assertTrue(r.body().contains("error"), r.body())
        }
    }

    @Test
    fun `accepts a STARTTLS listener via the API`() {
        val port = freePort()
        val r = post("/listeners",
            """{"name":"stls","protocol":"tcp","bind_port":$port,"upstream_host":"127.0.0.1","upstream_port":25,"tls":"starttls"}""")
        assertEquals(200, r.statusCode(), r.body())
        assertTrue(get("/status").body().contains("stls"))
    }
}
