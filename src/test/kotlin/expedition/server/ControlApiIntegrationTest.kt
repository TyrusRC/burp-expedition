package expedition.server

import expedition.intercept.InterceptController
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
    private lateinit var intercept: InterceptController
    private var port = 0
    private val http = HttpClient.newHttpClient()

    @BeforeEach
    fun setUp() {
        port = ServerSocket(0).use { it.localPort }
        registry = ConnectionRegistry()
        matchReplace = MatchReplaceEngine()
        intercept = InterceptController()
        server = ControlApiServer(
            host = "127.0.0.1", port = port,
            registry = registry, matchReplace = matchReplace, intercept = intercept,
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
    fun `an invalid regex match-replace rule is rejected with 400 and not registered`() {
        val r = post("/matchreplace", """{"match_type":"REGEX","match":"(unclosed","replace":"x"}""")
        assertEquals(400, r.statusCode(), r.body())
        assertTrue(r.body().contains("error"), r.body())
        assertEquals(0, matchReplace.rules().size, "a rule that can't compile must never enter the engine")
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

    /** Send a raw GET /status with extra headers; return the HTTP status line. */
    private fun rawStatusLine(vararg headers: String): String =
        java.net.Socket("127.0.0.1", port).use { s ->
            val req = StringBuilder("GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            headers.forEach { req.append(it).append("\r\n") }
            req.append("Connection: close\r\n\r\n")
            s.getOutputStream().write(req.toString().toByteArray()); s.getOutputStream().flush()
            s.getInputStream().bufferedReader().readLine()
        }

    // CSRF / DNS-rebinding defense: a browser fetch from a malicious page always carries
    // an Origin header; a legitimate CLI/MCP client carries none. Any cross-site Origin
    // must be rejected even though the Host is loopback (a no-cors POST is otherwise a
    // simple request the browser lets through).
    @Test
    fun `a cross-site Origin header is rejected`() {
        assertTrue(rawStatusLine("Origin: http://evil.com").contains("403"))
    }

    @Test
    fun `a request with no Origin header is allowed`() {
        assertTrue(rawStatusLine().contains("200"))
    }

    @Test
    fun `a loopback Origin header is allowed`() {
        assertTrue(rawStatusLine("Origin: http://127.0.0.1:$port").contains("200"))
    }

    @Test
    fun `when an auth token is set, only requests carrying it are served`() {
        val p = ServerSocket(0).use { it.localPort }
        val secured = ControlApiServer(
            host = "127.0.0.1", port = p,
            registry = ConnectionRegistry(), matchReplace = MatchReplaceEngine(), intercept = InterceptController(),
            startListener = {}, stopListener = {}, runningListeners = { emptySet() },
            authToken = "s3cret",
        )
        secured.start()
        try {
            fun status(auth: String?): Int {
                val b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:$p/status"))
                if (auth != null) b.header("Authorization", auth)
                return http.send(b.build(), HttpResponse.BodyHandlers.ofString()).statusCode()
            }
            assertEquals(401, status(null), "no token must be rejected")
            assertEquals(401, status("Bearer wrong"), "wrong token must be rejected")
            assertEquals(200, status("Bearer s3cret"), "correct token must be served")
        } finally {
            secured.stop()
        }
    }

    @Test
    fun `an oversized request body is rejected`() {
        val big = "x".repeat(5 * 1024 * 1024) // 5 MiB, over the cap
        val r = post("/matchreplace", """{"match_type":"LITERAL_STRING","match":"$big","replace":"y"}""")
        assertEquals(400, r.statusCode(), "oversized body should be rejected, not buffered whole")
        assertEquals(0, matchReplace.rules().size)
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
    fun `intercept enable, list held, and forward`() {
        assertEquals(200, post("/intercept/enable", """{"enabled":true}""").statusCode())
        assertTrue(intercept.isEnabled())

        // hold a message the way MessageGate would, then confirm the API sees + forwards it.
        var held = -1L
        val fut = intercept.intercept("PING".toByteArray()) { id, bytes ->
            intercept.recordHeld(id, 7L, "CLIENT_TO_UPSTREAM", bytes); held = id
        }
        val state = get("/intercept").body()
        assertTrue(state.contains("\"held\""))
        assertTrue(state.contains("\"connection_id\":7"), state)

        val fwd = post("/intercept/$held/forward", """{"text":"PONG"}""")
        assertEquals(200, fwd.statusCode())
        val decision = fut.get()
        assertTrue(decision is expedition.intercept.InterceptDecision.Forward)
        assertEquals("PONG", String((decision as expedition.intercept.InterceptDecision.Forward).bytes))
        assertTrue(intercept.heldMessages().isEmpty())   // cleared after forward
    }

    @Test
    fun `status exposes the exact fields the MCP client reads`() {
        // tcp_proxy_status reads: version, running_listeners, connections, messages
        val b = get("/status").body()
        for (f in listOf("\"version\"", "\"running_listeners\"", "\"connections\"", "\"messages\""))
            assertTrue(b.contains(f), "status missing $f: $b")
    }
}
