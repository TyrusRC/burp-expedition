package expedition.server

import expedition.dns.DnsController
import expedition.engine.ListenerConfig
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
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

/** Control API guards: non-loopback opt-in, UDP option rejection, and query-string decoding over HTTP. */
class ControlApiGuardsTest {

    private val started = mutableListOf<ListenerConfig>()
    private val registry = ConnectionRegistry()
    private lateinit var server: ControlApiServer
    private var apiPort = 0
    private val http = HttpClient.newHttpClient()

    @BeforeEach
    fun setUp() {
        apiPort = ServerSocket(0).use { it.localPort }
        server = ControlApiServer(
            authToken = TEST_TOKEN,
            host = "127.0.0.1", port = apiPort,
            registry = registry, matchReplace = MatchReplaceEngine(), intercept = InterceptController(),
            startListener = { started += it },
            stopListener = {},
            runningListeners = { emptySet() },
            dnsController = DnsController(onError = {}),
        )
        server.start()
    }

    @AfterEach
    fun tearDown() = server.stop()

    private fun post(path: String, body: String): HttpResponse<String> =
        http.send(
            authed(URI.create("http://127.0.0.1:$apiPort$path"))
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString())

    private fun get(path: String): HttpResponse<String> =
        http.send(authed(URI.create("http://127.0.0.1:$apiPort$path")).build(),
            HttpResponse.BodyHandlers.ofString())

    private fun listener(extra: String = "", bindHost: String = "127.0.0.1", protocol: String = "tcp") =
        """{"name":"l1","protocol":"$protocol","bind_host":"$bindHost","bind_port":9000,""" +
            """"upstream_host":"10.0.0.1","upstream_port":80$extra}"""

    @Test
    fun `non-loopback bind_host is refused without allow_non_loopback`() {
        val r = post("/listeners", listener(bindHost = "0.0.0.0"))
        assertEquals(400, r.statusCode())
        assertTrue(r.body().contains("allow_non_loopback"), r.body())
        assertTrue(started.isEmpty())
    }

    @Test
    fun `non-loopback bind_host is accepted with allow_non_loopback true`() {
        val r = post("/listeners", listener(extra = ",\"allow_non_loopback\":true", bindHost = "0.0.0.0"))
        assertEquals(200, r.statusCode(), r.body())
        assertEquals(listOf("0.0.0.0"), started.map { it.bindHost })
    }

    @Test
    fun `loopback bind_host needs no opt-in`() {
        val r = post("/listeners", listener(bindHost = "::1"))
        assertEquals(200, r.statusCode(), r.body())
    }

    @Test
    fun `dns start refuses a non-loopback host without opt-in`() {
        val r = post("/dns/start", """{"host":"0.0.0.0","rules":[{"host":"a.test","ip":"127.0.0.1"}]}""")
        assertEquals(400, r.statusCode())
        assertTrue(r.body().contains("allow_non_loopback"), r.body())
    }

    @Test
    fun `udp listener rejects upstream_proxy`() {
        val r = post("/listeners", listener(protocol = "udp", extra = ",\"upstream_proxy\":\"10.0.0.2:3128\""))
        assertEquals(400, r.statusCode())
        assertTrue(r.body().contains("not supported for UDP"), r.body())
        assertTrue(started.isEmpty())
    }

    @Test
    fun `search decodes plus and percent escapes in q`() {
        val c = registry.openConnection("l", expedition.registry.Protocol.TCP, "c", "u")
        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, "say hello world".toByteArray())
        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, "a+b=c".toByteArray())
        // `+` is a space in form encoding, so "hello+world" finds "hello world".
        assertTrue(get("/messages/search?q=hello+world").body().contains("hello world"))
        // %2B is a literal plus; %3D is '='.
        val r = get("/messages/search?q=a%2Bb%3Dc")
        assertEquals(200, r.statusCode())
        assertTrue(r.body().contains("a+b=c"), r.body())
    }
}
