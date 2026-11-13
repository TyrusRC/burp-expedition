package expedition.analysis

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/** A parsed HTTP/1.x message (request or response). [body] is the wire body (still content-encoded). */
class HttpMsg(val startLine: String, val headers: List<Pair<String, String>>, val body: ByteArray, val truncated: Boolean) {
    /** All values of [name] joined with ", " (case-insensitive), or null when absent. */
    fun header(name: String): String? {
        val v = headers.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }
        return if (v.isEmpty()) null else v.joinToString(", ")
    }
    val method: String get() = startLine.substringBefore(' ')
    val target: String get() = startLine.substringAfter(' ', "").substringBeforeLast(' ')
    val status: Int get() = startLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
    val contentType: String? get() = header("content-type")?.substringBefore(';')?.trim()?.lowercase()
}

class HttpExchange(val connectionId: Long, val request: HttpMsg, val response: HttpMsg?) {
    val label: String get() = "${request.method} ${request.target}" + (response?.let { " -> ${it.status}" } ?: " (no response)")
}

object HttpExchanges {
    const val MAX_DECODED = 4 * 1024 * 1024

    private val REQ_LINE = Regex("^[A-Z]+ \\S+ HTTP/1\\.[01]$")
    private val RES_LINE = Regex("^HTTP/1\\.[01] \\d{3}( .*)?$")

    /** Reassembles each direction's byte stream of one connection and pairs requests with responses in order. */
    fun extract(connectionId: Long, messages: List<ProxyMessage>): List<HttpExchange> {
        val up = ByteArrayOutputStream(); val down = ByteArrayOutputStream()
        for (m in messages) if (!m.isNote) (if (m.direction == Direction.CLIENT_TO_UPSTREAM) up else down).write(m.rawBytes)
        val reqs = parseStream(up.toByteArray(), true, emptyList())
        if (reqs.isEmpty()) return emptyList()
        val resps = parseStream(down.toByteArray(), false, reqs.map { it.method })
        return reqs.mapIndexed { i, r -> HttpExchange(connectionId, r, resps.getOrNull(i)) }
    }

    fun parseStream(buf: ByteArray, isRequest: Boolean, methods: List<String>): List<HttpMsg> {
        val out = ArrayList<HttpMsg>()
        var pos = 0
        var respIdx = 0
        while (pos < buf.size && out.size < 10_000) {
            val end = indexOf(buf, HEADER_END, pos)
            if (end < 0) break
            val head = String(buf, pos, end - pos, Charsets.ISO_8859_1).split("\r\n")
            val start = head[0]
            if (!(if (isRequest) REQ_LINE else RES_LINE).matches(start)) break
            val headers = head.drop(1).mapNotNull { l ->
                val c = l.indexOf(':'); if (c <= 0) null else l.substring(0, c).trim() to l.substring(c + 1).trim()
            }
            var bodyStart = end + 4
            val proto = HttpMsg(start, headers, ByteArray(0), false)
            val status = if (isRequest) 0 else proto.status
            if (!isRequest && status in 100..199) { pos = bodyStart; continue } // interim response
            val method = if (isRequest) proto.method else methods.getOrElse(respIdx) { "GET" }
            if (!isRequest) respIdx++
            val chunked = proto.header("transfer-encoding")?.lowercase()?.contains("chunked") == true
            val cl = proto.header("content-length")?.trim()?.toLongOrNull()
            val noBody = !isRequest && (method == "HEAD" || status == 204 || status == 304)
            val body: ByteArray; var trunc = false
            when {
                noBody -> { body = ByteArray(0) }
                chunked -> {
                    val bo = ByteArrayOutputStream(); var p = bodyStart; var done = false
                    while (true) {
                        val le = indexOf(buf, CRLF, p); if (le < 0) break
                        val size = String(buf, p, le - p, Charsets.ISO_8859_1).substringBefore(';').trim().toIntOrNull(16) ?: break
                        p = le + 2
                        if (size == 0) {
                            val te = indexOf(buf, HEADER_END, p - 2) // skip trailers
                            p = if (te >= 0) te + 4 else buf.size; done = true; break
                        }
                        if (p + size > buf.size) { bo.write(buf, p, buf.size - p); p = buf.size; break }
                        bo.write(buf, p, size); p += size + 2
                    }
                    trunc = !done; body = bo.toByteArray(); bodyStart = minOf(p, buf.size)
                }
                cl != null -> {
                    val n = minOf(cl, (buf.size - bodyStart).toLong()).toInt()
                    trunc = n < cl; body = buf.copyOfRange(bodyStart, bodyStart + n); bodyStart += n
                }
                isRequest -> body = ByteArray(0)
                else -> { body = buf.copyOfRange(bodyStart, buf.size); bodyStart = buf.size }
            }
            out.add(HttpMsg(start, headers, body, trunc))
            pos = bodyStart
        }
        return out
    }

    /** Decodes gzip/deflate bodies (capped at [MAX_DECODED]); identity returns as-is; br/zstd/unknown return null. */
    fun decodedBody(m: HttpMsg): ByteArray? {
        val encs = (m.header("content-encoding") ?: "").split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() && it != "identity" }
        var data = m.body
        for (e in encs.reversed()) {
            data = when (e) {
                "gzip", "x-gzip" -> inflate(data) { GZIPInputStream(ByteArrayInputStream(it)) }
                "deflate" -> inflate(data) { InflaterInputStream(ByteArrayInputStream(it)) }
                    ?: inflate(data) { InflaterInputStream(ByteArrayInputStream(it), Inflater(true)) }
                else -> null
            } ?: return null
        }
        return data
    }

    private fun inflate(data: ByteArray, open: (ByteArray) -> java.io.InputStream): ByteArray? = try {
        open(data).use { s ->
            val bo = ByteArrayOutputStream(); val b = ByteArray(8192)
            while (true) {
                val n = s.read(b); if (n < 0) break
                bo.write(b, 0, n); if (bo.size() > MAX_DECODED) break
            }
            bo.toByteArray()
        }
    } catch (_: Exception) { null }

    private val HEADER_END = "\r\n\r\n".toByteArray()
    private val CRLF = "\r\n".toByteArray()

    private fun indexOf(h: ByteArray, n: ByteArray, from: Int): Int {
        var i = maxOf(from, 0)
        while (i <= h.size - n.size) {
            var j = 0
            while (j < n.size && h[i + j] == n[j]) j++
            if (j == n.size) return i
            i++
        }
        return -1
    }
}
