package expedition.rules

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import kotlin.random.Random

class HttpStreamParserTest {

    private fun b(s: String) = s.toByteArray(Charsets.ISO_8859_1)

    /** Feeds [stream] in random-sized pieces and rebuilds messages; also checks byte conservation. */
    private class Collected(val heads: List<HttpHead>, val bodies: List<String>, val ends: Int, val raw: ByteArray, val wire: ByteArray)

    private fun collect(stream: ByteArray, request: Boolean, seed: Int, methods: List<String> = emptyList()): Collected {
        val heads = ArrayList<HttpHead>()
        val bodies = ArrayList<String>()
        var cur = ByteArrayOutputStream()
        var ends = 0
        val raw = ByteArrayOutputStream()
        val wire = ByteArrayOutputStream()
        val rnd = Random(seed)
        var p = 0
        fun handle(events: List<HttpEvent>) {
            for (e in events) {
                wire.write(e.wire)
                when (e) {
                    is HttpEvent.Head -> if (!e.interim) heads += e.head
                    is HttpEvent.Body -> cur.write(e.data)
                    HttpEvent.End -> { bodies += cur.toString(Charsets.ISO_8859_1); cur = ByteArrayOutputStream(); ends++ }
                    is HttpEvent.Raw -> raw.write(e.wire)
                }
            }
        }
        // methodForResponse is consulted when a response head completes: it answers request #heads.size
        val use = HttpStreamParser(request, { methods.getOrNull(heads.size) })
        while (p < stream.size) {
            val n = minOf(stream.size - p, 1 + rnd.nextInt(7))
            handle(use.feed(stream.copyOfRange(p, p + n)))
            p += n
        }
        handle(use.finish())
        return Collected(heads, bodies, ends, raw.toByteArray(), wire.toByteArray())
    }

    private val pipelined = b(
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" +
            "POST /b?q=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" +
            "PUT /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "3;ext=1\r\nabc\r\n4\r\ndefg\r\n0\r\nX-Trailer: t\r\n\r\n" +
            "\r\nDELETE /d HTTP/1.0\r\nHost: x\r\n\r\n",
    )

    @Test
    fun `requests split at arbitrary boundaries parse identically (keep-alive, chunked, trailers)`() {
        repeat(40) { seed ->
            val c = collect(pipelined, true, seed)
            assertEquals(listOf("GET", "POST", "PUT", "DELETE"), c.heads.map { it.method }, "seed $seed")
            assertEquals(listOf("", "hello", "abcdefg", ""), c.bodies, "seed $seed")
            assertEquals(4, c.ends)
            assertEquals(0, c.raw.size)
            assertEquals("/b?q=1", c.heads[1].originTarget)
            assertEquals("/b", c.heads[1].path)
        }
    }

    @Test
    fun `every byte fed comes out in exactly one event`() {
        val c = collect(pipelined, true, 7)
        // leading blank line before DELETE is swallowed into its head
        assertArrayEquals(pipelined, c.wire)
    }

    @Test
    fun `responses - content-length, chunked, interim 100, HEAD and 204 have no body, until-close`() {
        val stream = b(
            "HTTP/1.1 100 Continue\r\n\r\n" +
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc" +
                "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n" +          // answer to HEAD: no body
                "HTTP/1.1 204 No Content\r\n\r\n" +
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" +
                "HTTP/1.1 200 OK\r\n\r\nrest-until-close",
        )
        repeat(20) { seed ->
            val c = collect(stream, false, seed, listOf("POST", "HEAD", "GET", "GET", "GET"))
            assertEquals(listOf(200, 200, 204, 200, 200), c.heads.map { it.status }, "seed $seed")
            assertEquals(listOf("abc", "", "", "hello", "rest-until-close"), c.bodies, "seed $seed")
        }
    }

    @Test
    fun `101 switching protocols turns the stream raw after the head`() {
        val p = HttpStreamParser(false, { "GET" })
        val ev = p.feed(b("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\u0081\u0002hi"))
        assertTrue(ev[0] is HttpEvent.Head)
        assertTrue(ev[1] === HttpEvent.End)
        assertEquals("\u0081\u0002hi", String((ev[2] as HttpEvent.Raw).wire, Charsets.ISO_8859_1))
        assertTrue(p.isRaw)
    }

    @Test
    fun `non-HTTP input goes raw on the first bytes instead of waiting for a blank line`() {
        val bin = HttpStreamParser(true)
        val ev = bin.feed(byteArrayOf(0x16, 0x03, 0x01, 0x00))
        assertTrue(ev.single() is HttpEvent.Raw)
        assertTrue(bin.isRaw)

        // a text protocol: decided when the first line ends
        val smtp = HttpStreamParser(true)
        assertTrue(smtp.feed(b("EHLO")).isEmpty())
        val ev2 = smtp.feed(b(" example.org\r\n"))
        assertEquals("EHLO example.org\r\n", String((ev2.single() as HttpEvent.Raw).wire, Charsets.ISO_8859_1))

        // server-first banner seen by a response parser
        val banner = HttpStreamParser(false)
        assertTrue(banner.feed(b("220 mail ESMTP\r\n")).single() is HttpEvent.Raw)
    }

    @Test
    fun `parseHttpStream rebuilds exchanges with spans`() {
        val reqs = parseHttpStream(pipelined, true)
        assertEquals(4, reqs.size)
        assertEquals("hello", String(reqs[1].body))
        assertTrue(reqs.all { it.complete })
        assertEquals(0, reqs[0].start)
        assertEquals(reqs[0].end, reqs[1].start)
    }

    @Test
    fun `head helpers - host from header or absolute form, set and remove`() {
        val h = HttpHead.parse("GET http://Example.com:8080/x?y HTTP/1.1\r\nHost: other\r\nA: 1\r\na: 2", true)!!
        assertEquals("Example.com", h.host)
        assertEquals("/x?y", h.originTarget)
        assertEquals("1, 2", h.header("A"))
        val h2 = h.set("a", "3").remove("host")
        assertEquals("3", h2.header("a"))
        assertFalse(h2.has("Host"))
        assertEquals(null, HttpHead.parse("garbage", true))
        assertEquals("::1", HttpHead.parse("GET / HTTP/1.1\r\nHost: [::1]:80", true)!!.host)
    }
}
