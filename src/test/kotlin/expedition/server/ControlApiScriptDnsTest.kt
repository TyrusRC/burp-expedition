package expedition.server

import expedition.dns.DnsController
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.script.ScriptHooks
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

class ControlApiScriptDnsTest {

    private lateinit var server: ControlApiServer
    private lateinit var dns: DnsController
    private var port = 0
    private val http = HttpClient.newHttpClient()

    @BeforeEach fun setUp() {
        port = ServerSocket(0).use { it.localPort }
        dns = DnsController()
        server = ControlApiServer(
            host = "127.0.0.1", port = port,
            registry = ConnectionRegistry(), matchReplace = MatchReplaceEngine(),
            intercept = InterceptController(),
            startListener = {}, stopListener = {}, runningListeners = { emptySet() },
            scriptHooks = ScriptHooks(), dnsController = dns,
        )
        server.start()
    }

    @AfterEach fun tearDown() { dns.stop(); server.stop() }

    private fun get(path: String) = http.send(
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path")).build(),
        HttpResponse.BodyHandlers.ofString())
    private fun post(path: String, body: String) = http.send(
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path"))
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
        HttpResponse.BodyHandlers.ofString())
    private fun delete(path: String) = http.send(
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path")).DELETE().build(),
        HttpResponse.BodyHandlers.ofString())

    @Test fun `script can be set, read back, and cleared`() {
        assertEquals(200, post("/script", """{"source":"'x'.getBytes()"}""").statusCode())
        val status = get("/script")
        assertEquals(200, status.statusCode())
        assertTrue(status.body().contains("\"installed\":true"), status.body())
        assertEquals(200, delete("/script").statusCode())
        assertTrue(get("/script").body().contains("\"installed\":false"))
    }

    @Test fun `an invalid script is rejected with 400`() {
        val r = post("/script", """{"source":"this is ((( not groovy"}""")
        assertEquals(400, r.statusCode(), r.body())
        assertTrue(r.body().contains("error"), r.body())
    }

    @Test fun `DNS starts on an ephemeral port, reports running, and stops`() {
        val start = post("/dns/start", """{"port":0,"rules":[{"host":"*","ip":"10.1.2.3"}]}""")
        assertEquals(200, start.statusCode(), start.body())
        assertTrue(start.body().contains("\"ok\":true"))
        assertTrue(get("/dns").body().contains("\"running\":true"))
        assertEquals(200, post("/dns/stop", "{}").statusCode())
        assertTrue(get("/dns").body().contains("\"running\":false"))
    }

    @Test fun `DNS start with neither rules nor default is rejected`() {
        assertEquals(400, post("/dns/start", """{"port":0}""").statusCode())
    }
}
