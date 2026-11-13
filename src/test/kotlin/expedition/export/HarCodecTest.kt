package expedition.export

import expedition.analysis.HttpExchanges
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.server.Json
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream

class HarCodecTest {
    private fun crlf(s: String) = s.replace("\n", "\r\n").toByteArray(Charsets.ISO_8859_1)
    private fun gzip(b: ByteArray) = ByteArrayOutputStream().also { o -> GZIPOutputStream(o).use { it.write(b) } }.toByteArray()

    private fun capture(r: ConnectionRegistry, up: String, req: ByteArray, res: ByteArray, split: Boolean = false): Long {
        val id = r.openConnection("l", Protocol.TCP, "c:1", up)
        r.recordMessage(id, Direction.CLIENT_TO_UPSTREAM, req)
        if (split) { r.recordMessage(id, Direction.UPSTREAM_TO_CLIENT, res.copyOfRange(0, 20)); r.recordMessage(id, Direction.UPSTREAM_TO_CLIENT, res.copyOfRange(20, res.size)) }
        else r.recordMessage(id, Direction.UPSTREAM_TO_CLIENT, res)
        r.closeConnection(id)
        return id
    }

    @Test fun exportsValidHar12WithGzipAndChunked() {
        val r = ConnectionRegistry()
        val gz = gzip("{\"hello\":\"world\"}".toByteArray())
        capture(r, "example.com:80",
            crlf("GET /a?q=1&r=%20x HTTP/1.1\nHost: example.com\nCookie: s=1; t=2\n\n"),
            crlf("HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Encoding: gzip\nContent-Length: ${gz.size}\nSet-Cookie: k=v; Path=/; HttpOnly\n\n") + gz)
        val chunked = crlf("HTTP/1.1 200 OK\nContent-Type: text/plain\nTransfer-Encoding: chunked\n\n5\nhello\n6\n world\n0\n\n")
        capture(r, "example.com:443", crlf("POST /p HTTP/1.1\nHost: example.com\nContent-Type: text/plain\nContent-Length: 2\n\nhi"), chunked, split = true)
        val udp = r.openConnection("u", Protocol.UDP, "c", "8.8.8.8:53"); r.recordMessage(udp, Direction.CLIENT_TO_UPSTREAM, byteArrayOf(1, 2))
        val tcpBinary = r.openConnection("t", Protocol.TCP, "c", "x:1"); r.recordMessage(tcpBinary, Direction.CLIENT_TO_UPSTREAM, byteArrayOf(1, 2))

        val exp = HarCodec.export(r)
        assertEquals(2, exp.entries)
        assertEquals(2, exp.skippedConnections)
        val log = Json.asObject(Json.asObject(Json.parse(exp.json))["log"])
        assertEquals("1.2", log["version"])
        val entries = log["entries"] as List<*>
        val e0 = Json.asObject(entries[0]); val e1 = Json.asObject(entries[1])
        val req0 = Json.asObject(e0["request"]); val res0 = Json.asObject(e0["response"])
        assertEquals("http://example.com/a?q=1&r=%20x", req0["url"])
        assertEquals(2, (req0["queryString"] as List<*>).size)
        assertEquals(2, (req0["cookies"] as List<*>).size)
        assertEquals("{\"hello\":\"world\"}", Json.asObject(res0["content"])["text"])
        assertEquals(gz.size.toDouble(), (res0["bodySize"] as Number).toDouble())
        assertEquals("k", Json.asObject((res0["cookies"] as List<*>)[0])["name"])
        assertEquals("https://example.com/p", Json.asObject(e1["request"])["url"])
        assertEquals("hello world", Json.asObject(Json.asObject(e1["response"])["content"])["text"])
        assertEquals("hi", Json.asObject(Json.asObject(e1["request"])["postData"])["text"])
        for (e in entries) for (k in listOf("startedDateTime", "time", "request", "response", "cache", "timings"))
            assertTrue(Json.asObject(e).containsKey(k), k)
    }

    @Test fun roundTripGzipAndChunkedAndBinary() {
        val src = ConnectionRegistry()
        val gz = gzip("{\"hello\":\"world\"}".toByteArray())
        capture(src, "example.com:80", crlf("GET /a HTTP/1.1\nHost: example.com\n\n"),
            crlf("HTTP/1.1 200 OK\nContent-Encoding: gzip\nContent-Length: ${gz.size}\n\n") + gz)
        capture(src, "example.com:80", crlf("POST /p HTTP/1.1\nHost: example.com\nContent-Length: 2\n\nhi"),
            crlf("HTTP/1.1 201 Created\nTransfer-Encoding: chunked\n\n5\nhello\n6\n world\n0\n\n"))
        val bin = byteArrayOf(0, 1, 2, 0xff.toByte(), 0x80.toByte())
        capture(src, "example.com:80", crlf("PUT /b HTTP/1.1\nHost: example.com\nContent-Length: 5\n\n") + bin,
            crlf("HTTP/1.1 200 OK\nContent-Type: application/octet-stream\nContent-Length: 5\n\n") + bin)

        val har = HarCodec.export(src).json
        val dst = ConnectionRegistry()
        val imp = HarCodec.import(dst, har)
        assertEquals(3, imp.connectionsAdded); assertEquals(6, imp.messagesAdded); assertEquals(0, imp.skippedEntries)

        val ex = dst.allConnections().flatMap { HttpExchanges.extract(it.connectionId, dst.messagesFor(it.connectionId)) }
        assertEquals(3, ex.size)
        // gzip response is re-compressed and decodes to the same plaintext
        assertEquals("gzip", ex[0].response!!.header("content-encoding"))
        assertEquals("{\"hello\":\"world\"}", String(HttpExchanges.decodedBody(ex[0].response!!)!!))
        // chunked response arrives as a Content-Length body
        assertEquals("hello world", String(ex[1].response!!.body))
        assertEquals(201, ex[1].response!!.status)
        assertEquals("hi", String(ex[1].request.body))
        // binary survives byte for byte
        assertArrayEquals(bin, ex[2].request.body)
        assertArrayEquals(bin, ex[2].response!!.body)
        assertEquals("example.com:80", dst.allConnections()[0].upstreamAddress)
    }

    @Test fun importCountsSkippedAndHandlesChromeStyle() {
        val har = """{"log":{"version":"1.2","entries":[
          {"startedDateTime":"2024-01-01T00:00:00.000Z","time":12,"request":{"method":"POST","url":"https://a.test:8443/x?y=1","httpVersion":"h2",
            "headers":[{"name":":authority","value":"a.test:8443"},{"name":"content-type","value":"application/x-www-form-urlencoded"}],
            "postData":{"mimeType":"application/x-www-form-urlencoded","params":[{"name":"a","value":"b c"}]}},
           "response":{"status":200,"statusText":"","httpVersion":"h2","headers":[{"name":"content-encoding","value":"br"}],"content":{"mimeType":"text/plain","text":"plain"}}},
          {"request":{"method":"GET","url":"ws://nope"}},
          {"nonsense":true}]}}"""
        val r = ConnectionRegistry()
        val res = HarCodec.import(r, har)
        assertEquals(1, res.entries); assertEquals(2, res.skippedEntries)
        assertEquals("a.test:8443", r.allConnections()[0].upstreamAddress)
        val ex = HttpExchanges.extract(1, r.messagesFor(r.allConnections()[0].connectionId)).single()
        assertEquals("a.test:8443", ex.request.header("host"))
        assertEquals("a=b+c", String(ex.request.body))
        assertEquals("/x?y=1", ex.request.target)
        assertEquals("plain", String(ex.response!!.body))
        assertEquals(null, ex.response!!.header("content-encoding")) // br cannot be re-applied
    }

    @Test fun rejectsNonHar() {
        assertThrows(IllegalArgumentException::class.java) { HarCodec.import(ConnectionRegistry(), "{}") }
        assertThrows(IllegalArgumentException::class.java) { HarCodec.import(ConnectionRegistry(), "nope") }
    }

    @Test fun apiSnippetAndTargets() {
        val r = ConnectionRegistry()
        val id = capture(r, "example.com:443", crlf("GET /z HTTP/1.1\nHost: example.com\n\n"), crlf("HTTP/1.1 204 No Content\n\n"))
        assertTrue(ExportApi.snippet(r, null, null, null).contains("python-requests"))
        val out = Json.asObject(Json.parse(ExportApi.snippet(r, id.toString(), null, "curl")))
        assertEquals("curl 'https://example.com/z'", out["code"])
        assertThrows(IllegalArgumentException::class.java) { ExportApi.snippet(r, id.toString(), null, "cobol") }
        assertTrue(ExportApi.exportHar(r, id.toString()).contains("\"entries\""))
    }
}
