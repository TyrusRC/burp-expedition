package expedition.analysis

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream

class CompressionCacheAnalyzerTest {
    private val big = "<html>" + "hello world ".repeat(400) + "</html>"
    private fun get(extra: String = "") = "GET /x HTTP/1.1\nHost: a\n$extra\n\n"
    private fun codes(f: List<Finding>) = f.map { it.code }

    private fun gz(s: String): ByteArray {
        val bo = ByteArrayOutputStream(); GZIPOutputStream(bo).use { it.write(s.toByteArray()) }; return bo.toByteArray()
    }
    private fun gzExchange(reqExtra: String, resHeaders: String): HttpExchange {
        val body = gz(big)
        val raw = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n$resHeaders" +
            "Content-Length: ${body.size}\r\n\r\n").toByteArray(Charsets.ISO_8859_1) + body
        val req = HttpExchanges.parseStream(get(reqExtra).replace("\n", "\r\n").toByteArray(), true, emptyList())
        return HttpExchange(1, req[0], HttpExchanges.parseStream(raw, false, listOf("GET"))[0])
    }

    @Test fun `uncompressed large text warns when gzip accepted`() {
        val f = CompressionAnalyzer.analyze(exch(get("Accept-Encoding: gzip"), resp(200, "Content-Type: text/html", big)))
        assertEquals(listOf("compression.uncompressed-text"), codes(f))
        assertEquals(Severity.WARNING, f[0].severity)
    }

    @Test fun `uncompressed text is info when client did not advertise gzip`() {
        val f = CompressionAnalyzer.analyze(exch(get(), resp(200, "Content-Type: text/html", big)))
        assertEquals(Severity.INFO, f[0].severity)
    }

    @Test fun `small or binary bodies are ignored`() {
        assertTrue(CompressionAnalyzer.analyze(exch(get(), resp(200, "Content-Type: text/html", "tiny"))).isEmpty())
        assertTrue(CompressionAnalyzer.analyze(exch(get(), resp(200, "Content-Type: image/png", big))).isEmpty())
    }

    @Test fun `gzip response reports ratio and flags missing vary`() {
        val f = CompressionAnalyzer.analyze(gzExchange("Accept-Encoding: gzip\n", ""))
        assertTrue("compression.ratio" in codes(f)); assertTrue("compression.no-vary" in codes(f))
        val ok = CompressionAnalyzer.analyze(gzExchange("Accept-Encoding: gzip\n", "Vary: Accept-Encoding\r\n"))
        assertFalse("compression.no-vary" in codes(ok))
    }

    @Test fun `encoding not accepted and unrequested`() {
        assertTrue("compression.not-accepted" in codes(CompressionAnalyzer.analyze(gzExchange("Accept-Encoding: br\n", "Vary: Accept-Encoding\r\n"))))
        assertTrue("compression.not-accepted" in codes(CompressionAnalyzer.analyze(gzExchange("Accept-Encoding: gzip;q=0\n", "Vary: Accept-Encoding\r\n"))))
        assertTrue("compression.unrequested" in codes(CompressionAnalyzer.analyze(gzExchange("", "Vary: Accept-Encoding\r\n"))))
    }

    @Test fun `parseAccept reads q values`() {
        val m = CompressionAnalyzer.parseAccept("gzip;q=0.5, br, *;q=0")
        assertEquals(0.5, m["gzip"]); assertEquals(1.0, m["br"]); assertEquals(0.0, m["*"])
    }

    @Test fun `decodedBody roundtrips gzip`() {
        val x = gzExchange("", "")
        assertEquals(big, String(HttpExchanges.decodedBody(x.response!!)!!))
    }

    // ── cache ──
    private fun cache(h: String, req: String = get()) = CacheAnalyzer.analyze(exch(req, resp(200, h, "ok")))

    @Test fun `max-age verdict and summary`() {
        val v = CacheAnalyzer.verdict(exch(get(), resp(200, "Cache-Control: public, max-age=60", "ok")))!!
        assertTrue(v.cacheable); assertEquals(60L, v.ttlSeconds); assertEquals("shared", v.scope)
        assertEquals("private", CacheAnalyzer.verdict(exch(get(), resp(200, "Cache-Control: private, max-age=5", "ok")))!!.scope)
    }

    @Test fun `no-store and POST are not cacheable`() {
        assertFalse(CacheAnalyzer.verdict(exch(get(), resp(200, "Cache-Control: no-store", "ok")))!!.cacheable)
        assertFalse(CacheAnalyzer.verdict(exch("POST /x HTTP/1.1\nHost: a\n\n", resp(200, "Cache-Control: max-age=5", "ok")))!!.cacheable)
    }

    @Test fun `age reduces ttl and stale is reported`() {
        val x = exch(get(), resp(200, "Cache-Control: max-age=60\nAge: 100", "ok"))
        assertEquals(0L, CacheAnalyzer.verdict(x)!!.ttlSeconds)
        assertTrue("cache.stale" in codes(CacheAnalyzer.analyze(x)))
    }

    @Test fun `heuristic freshness from last-modified`() {
        val x = exch(get(), resp(200, "Date: Wed, 01 Jan 2025 00:00:00 GMT\nLast-Modified: Sat, 21 Dec 2024 00:00:00 GMT", "ok"))
        assertEquals(11L * 86400 / 10, CacheAnalyzer.verdict(x)!!.ttlSeconds)
    }

    @Test fun `expires relative to date`() {
        val x = exch(get(), resp(200, "Date: Wed, 01 Jan 2025 00:00:00 GMT\nExpires: Wed, 01 Jan 2025 01:00:00 GMT", "ok"))
        assertEquals(3600L, CacheAnalyzer.verdict(x)!!.ttlSeconds)
    }

    @Test fun `misconfigurations are flagged`() {
        assertTrue("cache.public-set-cookie" in codes(cache("Cache-Control: public, max-age=60\nSet-Cookie: a=b")))
        assertTrue("cache.no-store-with-validator" in codes(cache("Cache-Control: no-store\nETag: \"1\"")))
        assertTrue("cache.no-store-with-max-age" in codes(cache("Cache-Control: no-store, max-age=5")))
        assertTrue("cache.vary-star" in codes(cache("Cache-Control: max-age=5\nVary: *")))
        assertTrue("cache.public-and-private" in codes(cache("Cache-Control: public, private")))
        assertTrue("cache.invalid-expires" in codes(cache("Expires: 0")))
        assertTrue("cache.invalid-max-age" in codes(cache("Cache-Control: max-age=abc")))
        assertTrue("cache.public-authorization" in codes(cache("Cache-Control: public, max-age=5", get("Authorization: Bearer t"))))
        assertTrue("cache.shared-set-cookie" in codes(cache("Cache-Control: max-age=60\nSet-Cookie: a=b")))
        assertTrue("cache.max-age-zero-no-validator" in codes(cache("Cache-Control: max-age=0")))
        assertTrue("cache.no-headers" in codes(cache("")))
    }

    @Test fun `clean config only yields summary`() {
        assertEquals(listOf("cache.summary"), codes(cache("Cache-Control: public, max-age=60\nETag: \"1\"")))
    }
}
