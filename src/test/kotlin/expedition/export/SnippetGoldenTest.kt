package expedition.export

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.File

class SnippetGoldenTest {
    private fun raw(s: String) = s.replace("\n", "\r\n").toByteArray(Charsets.ISO_8859_1)

    private val textBody = "{\"name\":\"it's \$x\",\"t\":\"\u00e9\"}\n".toByteArray(Charsets.UTF_8)
    private val textReq = SnippetRequest.fromRaw(
        ("POST /v1/items?x=1&y=a%20b HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n" +
            "X-Token: a\"b\$c\\d\nAccept: text/html\nAccept: */*\nContent-Length: ${textBody.size}\n\n").let { raw(it) } + textBody,
        "api.example.com:443",
    )
    private val binReq = SnippetRequest.fromRaw(
        raw("PUT /up HTTP/1.1\nHost: files.example.com:8443\nContent-Type: application/octet-stream\nContent-Length: 7\n\n") +
            byteArrayOf(0, 1, 2, 0x7f, 0xff.toByte(), 0xfe.toByte(), 'a'.code.toByte()),
        "files.example.com:8443",
    )
    private val getReq = SnippetRequest.fromRaw(raw("GET /ping HTTP/1.1\nHost: localhost:8080\n\n"), "localhost:8080")

    private fun check(name: String, actual: String) {
        val f = File("src/test/resources/snippets/$name")
        if (System.getenv("GOLDEN_UPDATE") == "1") { f.parentFile.mkdirs(); f.writeText(actual); return }
        assertEquals(f.readText(), actual, "snippet drift for $name (rerun with GOLDEN_UPDATE=1 to regenerate)")
    }

    @Test fun twentyTargetsRegistered() {
        assertEquals(20, SnippetRegistry.all.size)
        assertEquals(20, SnippetRegistry.all.map { it.id }.toSet().size)
        assertNotNull(SnippetRegistry.get("CURL"))
    }

    @Test fun goldenText() { for (g in SnippetRegistry.all) check("${g.id}.txt", g.generate(textReq)) }
    @Test fun goldenBinary() { for (g in SnippetRegistry.all) check("${g.id}.bin.txt", g.generate(binReq)) }
    @Test fun goldenGet() { for (g in SnippetRegistry.all) check("${g.id}.get.txt", g.generate(getReq)) }

    @Test fun parsing() {
        assertEquals("https://api.example.com/v1/items?x=1&y=a%20b", textReq.url)
        assertEquals(listOf("Content-Type", "X-Token", "Accept", "Accept"), textReq.headers.map { it.first })
        assertEquals("text/html, */*", textReq.mergedHeaders.first { it.first == "Accept" }.second)
        assertEquals(true, binReq.isBinary)
        assertEquals(8443, binReq.port)
        assertThrows(IllegalArgumentException::class.java) { SnippetRequest.fromRaw("garbage".toByteArray()) }
    }

    @Test fun curlEscapesSingleQuote() {
        val out = SnippetRegistry.get("curl")!!.generate(textReq)
        assert(out.contains("it'\\''s")) { out }
    }
}
