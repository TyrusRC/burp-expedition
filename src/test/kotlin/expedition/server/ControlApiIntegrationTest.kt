package expedition.server

import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class ControlApiIntegrationTest {

    private lateinit var server: ControlApiServer
    private lateinit var registry: ConnectionRegistry
    private lateinit var matchReplace: MatchReplaceEngine
    private var port = 0
    private val http = HttpClient.newHttpClient()

    @BeforeEach
    fun setUp() {
        port = ServerSocket(0).use { it.localPort }
        registry = ConnectionRegistry()
        matchReplace = MatchReplaceEngine()
        server = ControlApiServer(
            host = "127.0.0.1", port = port,
            registry = registry, matchReplace = matchReplace,
            startListener = {}, stopListener = {}, runningListeners = { setOf("redis") },
        )
        server.start()
    }

    @AfterEach
    fun tearDown() = server.stop()

    private fun get(path: String): HttpResponse<String> =
        http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path")).build(),
                  HttpResponse.BodyHandlers.ofString())

    private fun post(path: String, body: String): HttpResponse<String> =
        http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path"))
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString())

    @Test
    fun `status reports running listeners`() {
        val r = get("/status")
        assertEquals(200, r.statusCode())
        assertTrue(r.body().contains("\"running_listeners\":[\"redis\"]"), r.body())
    }

    @Test
    fun `match-replace add then list round-trips through the engine`() {
        val add = post("/matchreplace", """{"match_type":"LITERAL_STRING","match":"foo","replace":"bar"}""")
        assertEquals(200, add.statusCode())
        assertTrue(add.body().contains("\"ok\":true"))
        assertEquals(1, matchReplace.rules().size)
        val list = get("/matchreplace")
        assertTrue(list.body().contains("\"match\":\"foo\""), list.body())
        // and the engine actually applies it
        assertEquals("bar", String(matchReplace.apply("foo".toByteArray())))
    }

    @Test
    fun `non-loopback Host header is rejected`() {
        // java.net.http forbids overriding Host, so send a raw request.
        java.net.Socket("127.0.0.1", port).use { s ->
            s.getOutputStream().write(
                "GET /status HTTP/1.1\r\nHost: evil.com\r\nConnection: close\r\n\r\n"
                    .toByteArray())
            s.getOutputStream().flush()
            val statusLine = s.getInputStream().bufferedReader().readLine()
            assertTrue(statusLine.contains("403"), statusLine)
        }
    }

    @Test
    fun `bad listener config returns 400`() {
        val r = post("/listeners", """{"protocol":"tcp"}""")   // missing name/upstream
        assertEquals(400, r.statusCode())
        assertTrue(r.body().contains("error"))
    }

    // ── Full Python-client contract: assert the exact field names the MCP
    //    tools (tools/expedition/tools.py) read back. ──────────────────────

    @Test
    fun `connections and messages expose the fields the MCP client reads`() {
        val cid = registry.openConnection("redis", Protocol.TCP, "1.2.3.4:5555", "10.0.0.5:6379")
        registry.recordMessage(cid, Direction.CLIENT_TO_UPSTREAM, "PING\r\n".toByteArray())

        val conns = get("/connections").body()
        // tcp_proxy_connections reads: id, protocol, client, upstream, listener, closed_at
        for (f in listOf("\"id\"", "\"protocol\"", "\"client\"", "\"upstream\"", "\"listener\"", "\"closed_at\""))
            assertTrue(conns.contains(f), "connections missing $f: $conns")

        val msgs = get("/connections/$cid/messages").body()
        // tcp_proxy_messages reads: id, connection_id, direction, length, hex, text
        for (f in listOf("\"connection_id\"", "\"direction\"", "\"length\"", "\"hex\"", "\"text\""))
            assertTrue(msgs.contains(f), "messages missing $f: $msgs")
        assertTrue(msgs.contains("CLIENT_TO_UPSTREAM"))
        assertTrue(get("/messages?limit=10").body().contains("\"hex\""))
    }

    @Test
    fun `repeat sends bytes to a target and returns the response fields`() {
        // local one-shot TCP echo
        val echo = ServerSocket(0)
        val echoPort = echo.localPort
        Thread {
            echo.accept().use { s ->
                val b = s.getInputStream().readNBytes(4)
                s.getOutputStream().write(b); s.getOutputStream().flush()
            }
        }.apply { isDaemon = true; start() }

        val r = post("/repeat", """{"protocol":"tcp","host":"127.0.0.1","port":$echoPort,"text":"ABCD"}""")
        assertEquals(200, r.statusCode())
        // tcp_repeat reads: sent_len, response_len, response_hex, response_text
        for (f in listOf("\"sent_len\"", "\"response_len\"", "\"response_hex\"", "\"response_text\""))
            assertTrue(r.body().contains(f), "repeat missing $f: ${r.body()}")
        assertTrue(r.body().contains("ABCD"), r.body())   // echoed back
        echo.close()
    }

    @Test
    fun `status exposes the exact fields the MCP client reads`() {
        // tcp_proxy_status reads: version, running_listeners, connections, messages
        val b = get("/status").body()
        for (f in listOf("\"version\"", "\"running_listeners\"", "\"connections\"", "\"messages\""))
            assertTrue(b.contains(f), "status missing $f: $b")
    }
}
