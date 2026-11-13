package expedition.server

import expedition.analysis.AnalysisService
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class ControlApiAnalysisTest {
    private lateinit var server: ControlApiServer
    private lateinit var registry: ConnectionRegistry
    private var port = 0
    private val http = HttpClient.newHttpClient()

    @BeforeEach fun setUp() {
        AnalysisService.clearOpenApi()
        port = ServerSocket(0).use { it.localPort }
        registry = ConnectionRegistry()
        server = ControlApiServer("127.0.0.1", port, registry, MatchReplaceEngine(), InterceptController(), {}, {}, { emptySet() }, authToken = TEST_TOKEN)
        server.start()
    }
    @AfterEach fun tearDown() { server.stop(); AnalysisService.clearOpenApi() }

    private fun get(p: String): HttpResponse<String> =
        http.send(authed(URI.create("http://127.0.0.1:$port$p")).build(), HttpResponse.BodyHandlers.ofString())
    private fun post(p: String, b: String): HttpResponse<String> =
        http.send(authed(URI.create("http://127.0.0.1:$port$p")).POST(HttpRequest.BodyPublishers.ofString(b)).build(), HttpResponse.BodyHandlers.ofString())

    private fun traffic(path: String, status: Int): Long {
        val id = registry.openConnection("l", Protocol.TCP, "c", "u")
        registry.recordMessage(id, Direction.CLIENT_TO_UPSTREAM, "GET $path HTTP/1.1\r\nHost: a\r\n\r\n".toByteArray())
        registry.recordMessage(id, Direction.UPSTREAM_TO_CLIENT, "HTTP/1.1 $status OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
        return id
    }

    private val spec = """{"openapi":"3.0.0","info":{"title":"T","version":"1"},"paths":{"/ok":{"get":{"responses":{"200":{"description":"x"}}}}}}"""

    @Test fun `report without spec has cache findings only`() {
        traffic("/ok", 200)
        val r = get("/analysis/report")
        assertEquals(200, r.statusCode())
        assertTrue(r.body().contains("\"openapi\":false"), r.body())
        assertTrue(r.body().contains("cache.summary"), r.body())
        assertFalse(r.body().contains("openapi.path-not-found"))
    }

    @Test fun `load spec then report flags violations and filters by connection`() {
        val a = traffic("/ok", 200); val b = traffic("/missing", 200)
        val l = post("/analysis/openapi", spec)
        assertEquals(200, l.statusCode()); assertTrue(l.body().contains("\"operations\":1"), l.body())
        val all = get("/analysis/report").body()
        assertTrue(all.contains("openapi.path-not-found"), all)
        val onlyA = get("/analysis/report?connection=$a").body()
        assertFalse(onlyA.contains("openapi.path-not-found"), onlyA)
        assertTrue(get("/analysis/report?connection=$b").body().contains("openapi.path-not-found"))
    }

    @Test fun `wrapped spec accepted, invalid spec 400, empty body clears`() {
        val wrapped = post("/analysis/openapi", """{"spec": ${Json.value(spec)}}""")
        assertEquals(200, wrapped.statusCode(), wrapped.body())
        assertEquals(400, post("/analysis/openapi", "swagger: '2.0'").statusCode())
        assertTrue(post("/analysis/openapi", "").body().contains("\"loaded\":false"))
        assertNull(AnalysisService.spec)
    }

    @Test fun `bad connection param is 400`() {
        assertEquals(400, get("/analysis/report?connection=abc").statusCode())
    }
}
