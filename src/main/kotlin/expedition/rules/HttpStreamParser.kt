package expedition.rules

import java.io.ByteArrayOutputStream

/** Start line + header fields of one HTTP/1.x message, in wire order. */
class HttpHead(val startLine: String, val headers: List<Pair<String, String>>) {
    val isResponse: Boolean get() = startLine.startsWith("HTTP/")

    /** All values of [name] joined with ", " (case-insensitive), or null when absent. */
    fun header(name: String): String? {
        val v = headers.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }
        return if (v.isEmpty()) null else v.joinToString(", ")
    }

    fun has(name: String): Boolean = headers.any { it.first.equals(name, ignoreCase = true) }

    val method: String get() = if (isResponse) "" else startLine.substringBefore(' ')
    val target: String get() = if (isResponse) "" else startLine.substringAfter(' ', "").substringBeforeLast(' ')
    val version: String get() = if (isResponse) startLine.substringBefore(' ') else startLine.substringAfterLast(' ')
    val status: Int get() = if (isResponse) startLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0 else 0
    val reason: String get() = if (isResponse) startLine.split(' ', limit = 3).getOrNull(2) ?: "" else ""

    /** Origin-form path+query (absolute-form `http://h/p?q` is reduced to `/p?q`). */
    val originTarget: String get() {
        val t = target
        if (!t.startsWith("http://", true) && !t.startsWith("https://", true)) return t
        val rest = t.substringAfter("://")
        val slash = rest.indexOf('/')
        return if (slash < 0) "/" else rest.substring(slash)
    }

    /** Path without the query string. */
    val path: String get() = originTarget.substringBefore('?')

    /** Host name from the Host header (or the absolute-form authority), without port; null if none. */
    val host: String? get() {
        val t = target
        val authority = if (t.startsWith("http://", true) || t.startsWith("https://", true))
            t.substringAfter("://").substringBefore('/') else header("host")?.trim()
        if (authority.isNullOrEmpty()) return null
        return if (authority.startsWith("[")) authority.substringAfter("[").substringBefore("]")
        else authority.substringBefore(':')
    }

    fun withHeaders(newHeaders: List<Pair<String, String>>) = HttpHead(startLine, newHeaders)
    fun withStartLine(line: String) = HttpHead(line, headers)

    fun set(name: String, value: String): HttpHead {
        var replaced = false
        val out = ArrayList<Pair<String, String>>()
        for (h in headers) {
            if (h.first.equals(name, ignoreCase = true)) {
                if (!replaced) { out += h.first to value; replaced = true }
            } else out += h
        }
        if (!replaced) out += name to value
        return HttpHead(startLine, out)
    }

    fun remove(name: String) = HttpHead(startLine, headers.filterNot { it.first.equals(name, ignoreCase = true) })

    fun toBytes(): ByteArray {
        val sb = StringBuilder(startLine).append("\r\n")
        headers.forEach { sb.append(it.first).append(": ").append(it.second).append("\r\n") }
        sb.append("\r\n")
        return sb.toString().toByteArray(Charsets.ISO_8859_1)
    }

    /** Serialise with [body] framed by Content-Length (Transfer-Encoding dropped). */
    fun withBody(body: ByteArray, forceLength: Boolean = true): ByteArray {
        var h = remove("Transfer-Encoding")
        if (forceLength) h = h.set("Content-Length", body.size.toString())
        return h.toBytes() + body
    }

    override fun toString() = startLine

    companion object {
        private val REQ_LINE = Regex("^[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]* \\S+ HTTP/1\\.[01]$")
        private val RES_LINE = Regex("^HTTP/1\\.[01] \\d{3}( .*)?$")

        /** True when [line] is a valid HTTP/1.x request (or status) line. */
        fun startLineOk(line: String, request: Boolean): Boolean = (if (request) REQ_LINE else RES_LINE).matches(line)

        /** Parse a header block (without the trailing blank line); null when it is not HTTP/1.x. */
        fun parse(text: String, request: Boolean): HttpHead? {
            val lines = text.trimStart('\r', '\n').split("\r\n")
            val start = lines.firstOrNull() ?: return null
            if (!(if (request) REQ_LINE else RES_LINE).matches(start)) return null
            val headers = ArrayList<Pair<String, String>>()
            for (l in lines.drop(1)) {
                if (l.isEmpty()) continue
                val c = l.indexOf(':')
                if (c <= 0) return null
                headers += l.substring(0, c).trim() to l.substring(c + 1).trim()
            }
            return HttpHead(start, headers)
        }
    }
}

/** One event from [HttpStreamParser]. Every byte fed comes out in exactly one event's [wire]. */
sealed class HttpEvent {
    abstract val wire: ByteArray

    /** A complete header block. [interim] = 1xx (not 101): the message is not finished by it. */
    class Head(val head: HttpHead, override val wire: ByteArray, val interim: Boolean, val untilClose: Boolean) : HttpEvent()

    /** Body bytes on the wire; [data] is the de-chunked payload part of them. */
    class Body(override val wire: ByteArray, val data: ByteArray) : HttpEvent()

    /** The current message is complete. */
    object End : HttpEvent() { override val wire = ByteArray(0) }

    /** Bytes that are not (or no longer) HTTP/1.x — the stream switched to raw relay. */
    class Raw(override val wire: ByteArray) : HttpEvent()
}

/**
 * Incremental, zero-rewrite HTTP/1.x parser for ONE direction of a connection. Handles
 * Content-Length, chunked (with trailers), read-until-close responses, 1xx interim responses,
 * HEAD/204/304 bodiless responses, keep-alive (any number of messages per stream) and pipelining.
 * Anything it cannot parse switches it to [HttpEvent.Raw] permanently, as does [switchToRaw]
 * (used after `101 Switching Protocols` / a successful CONNECT).
 *
 * Not thread-safe; owned by one session that serialises access.
 */
class HttpStreamParser(
    private val isRequest: Boolean,
    private val methodForResponse: () -> String? = { null },
    private val maxHeadBytes: Int = 64 * 1024,
) {
    private enum class S { HEAD, BODY_LEN, CHUNK_SIZE, CHUNK_DATA, CHUNK_CRLF, TRAILER, UNTIL_CLOSE, RAW }

    private var s = S.HEAD
    private val acc = Acc()
    private var remaining = 0L
    private var rawAfterEnd = false
    private var startChecked = false

    /** True between messages with nothing buffered (a safe point to change how the stream is handled). */
    val idle: Boolean get() = s == S.HEAD && acc.size() == 0
    val isRaw: Boolean get() = s == S.RAW

    /**
     * Why the stream went raw (set when the parser itself gave up, null after [switchToRaw]):
     * [REASON_HTTP2], [REASON_NOT_HTTP], [REASON_AMBIGUOUS] + detail, or [REASON_TOO_LARGE].
     */
    var rawReason: String? = null
        private set

    /** Switch to raw relay now; returns any bytes buffered for a not-yet-complete head. */
    fun switchToRaw(): ByteArray {
        s = S.RAW
        return acc.toByteArray().also { acc.reset() }
    }

    /** Connection closed: completes a read-until-close body; returns leftover partial bytes. */
    fun finish(): List<HttpEvent> {
        val out = ArrayList<HttpEvent>()
        if (acc.size() > 0) out += HttpEvent.Raw(acc.toByteArray()).also { acc.reset() }
        if (s == S.UNTIL_CLOSE) { out += HttpEvent.End; s = S.HEAD }
        return out
    }

    fun feed(chunk: ByteArray): List<HttpEvent> {
        val out = ArrayList<HttpEvent>()
        var p = 0
        while (p < chunk.size) {
            when (s) {
                S.RAW -> { out += HttpEvent.Raw(chunk.copyOfRange(p, chunk.size)); p = chunk.size }
                S.UNTIL_CLOSE -> { val b = chunk.copyOfRange(p, chunk.size); out += HttpEvent.Body(b, b); p = chunk.size }
                S.HEAD -> {
                    var found = false
                    while (p < chunk.size) {
                        acc.write(chunk[p].toInt()); p++
                        if (!startChecked) when (checkStart()) {
                            false -> { rawReason = if (looksLikeH2()) REASON_HTTP2 else REASON_NOT_HTTP; goRaw(out, chunk, p); return out }
                            true -> startChecked = true
                            null -> {}
                        }
                        if (endsWithBlankLine()) { found = true; break }
                    }
                    if (acc.size() > maxHeadBytes && !found) { rawReason = REASON_TOO_LARGE; goRaw(out, chunk, p); return out }
                    if (found) onHead(out)?.let { goRaw(out, chunk, p, it); return out }
                }
                S.BODY_LEN -> {
                    val n = minOf(remaining, (chunk.size - p).toLong()).toInt()
                    val b = chunk.copyOfRange(p, p + n); p += n; remaining -= n
                    out += HttpEvent.Body(b, b)
                    if (remaining == 0L) end(out)
                }
                S.CHUNK_SIZE, S.TRAILER -> {
                    var found = false
                    while (p < chunk.size) {
                        acc.write(chunk[p].toInt()); p++
                        if (endsWithCrlf()) { found = true; break }
                    }
                    if (!found) {
                        if (acc.size() > 8192) { goRaw(out, chunk, p); return out }
                        continue
                    }
                    val line = acc.toByteArray(); acc.reset()
                    out += HttpEvent.Body(line, ByteArray(0))
                    if (s == S.TRAILER) {
                        if (line.size == 2) end(out)
                    } else {
                        val size = String(line, Charsets.ISO_8859_1).trim().substringBefore(';').trim().toLongOrNull(16)
                        if (size == null || size < 0) { rawReason = "$REASON_AMBIGUOUS: bad chunk size"; s = S.RAW; out += HttpEvent.Raw(chunk.copyOfRange(p, chunk.size)); return out }
                        if (size == 0L) s = S.TRAILER else { remaining = size; s = S.CHUNK_DATA }
                    }
                }
                S.CHUNK_DATA -> {
                    val n = minOf(remaining, (chunk.size - p).toLong()).toInt()
                    val b = chunk.copyOfRange(p, p + n); p += n; remaining -= n
                    out += HttpEvent.Body(b, b)
                    if (remaining == 0L) { remaining = 2; s = S.CHUNK_CRLF }
                }
                S.CHUNK_CRLF -> {
                    val n = minOf(remaining, (chunk.size - p).toLong()).toInt()
                    out += HttpEvent.Body(chunk.copyOfRange(p, p + n), ByteArray(0)); p += n; remaining -= n
                    if (remaining == 0L) s = S.CHUNK_SIZE
                }
            }
        }
        return out
    }

    private fun goRaw(out: MutableList<HttpEvent>, chunk: ByteArray, p: Int, pending: ByteArray = acc.toByteArray()) {
        acc.reset()
        s = S.RAW
        out += HttpEvent.Raw(pending + chunk.copyOfRange(p, chunk.size))
    }

    private fun end(out: MutableList<HttpEvent>) {
        out += HttpEvent.End
        s = if (rawAfterEnd) S.RAW else S.HEAD
        rawAfterEnd = false
    }

    /** Parse the accumulated head; returns the bytes to emit raw if it is not HTTP. */
    private fun onHead(out: MutableList<HttpEvent>): ByteArray? {
        val wire = acc.toByteArray(); acc.reset()
        startChecked = false
        val text = String(wire, Charsets.ISO_8859_1)
        if (isRequest && HttpHead.startLineOk(text.trimStart('\r', '\n').substringBefore("\r\n"), true))
            headerLineProblem(text)?.let { rawReason = "$REASON_AMBIGUOUS: $it"; return wire }
        val head = HttpHead.parse(text, isRequest) ?: return wire.also { rawReason = REASON_NOT_HTTP }
        if (isRequest) ambiguousRequestFraming(head)?.let { rawReason = "$REASON_AMBIGUOUS: $it"; return wire }
        val chunked = head.header("transfer-encoding")?.lowercase()?.contains("chunked") == true
        val lengths = head.headers.filter { it.first.equals("content-length", true) }.map { it.second.trim() }.distinct()
        if (lengths.size > 1) return wire.also { rawReason = "$REASON_AMBIGUOUS: conflicting Content-Length" }
        val cl = lengths.firstOrNull()?.let { it.toLongOrNull() ?: return wire.also { rawReason = "$REASON_AMBIGUOUS: bad Content-Length" } }
        if (cl != null && cl < 0) return wire.also { rawReason = "$REASON_AMBIGUOUS: bad Content-Length" }
        if (isRequest) {
            out += HttpEvent.Head(head, wire, interim = false, untilClose = false)
            when {
                chunked -> s = S.CHUNK_SIZE
                cl != null && cl > 0 -> { remaining = cl; s = S.BODY_LEN }
                else -> end(out)
            }
            return null
        }
        val status = head.status
        val method = methodForResponse()?.uppercase() ?: "GET"
        if (status in 100..199 && status != 101) {
            out += HttpEvent.Head(head, wire, interim = true, untilClose = false)
            return null // still waiting for the final response
        }
        val noBody = method == "HEAD" || status == 204 || status == 304 || status == 101 ||
            (method == "CONNECT" && status in 200..299)
        if (status == 101 || (method == "CONNECT" && status in 200..299)) rawAfterEnd = true
        val untilClose = !noBody && !chunked && cl == null
        out += HttpEvent.Head(head, wire, interim = false, untilClose = untilClose)
        when {
            noBody -> end(out)
            chunked -> s = S.CHUNK_SIZE
            cl != null -> if (cl > 0) { remaining = cl; s = S.BODY_LEN } else end(out)
            else -> s = S.UNTIL_CLOSE
        }
        return null
    }

    /**
     * Early verdict on the start line so non-HTTP streams (binary, SMTP, ...) fall back to raw
     * relay after a few bytes instead of being buffered while waiting for a blank line.
     * null = undecided yet, true = valid start line, false = not HTTP/1.x.
     */
    private fun checkStart(): Boolean? {
        val n = acc.size()
        val b = acc.view()
        var i = 0
        while (i < n && (b[i] == CR || b[i] == LF)) i++
        if (i == n) return null
        val len = n - i
        if (b[n - 1] == LF) {
            val line = String(b, i, len, Charsets.ISO_8859_1).removeSuffix("\n").removeSuffix("\r")
            return HttpHead.startLineOk(line, isRequest)
        }
        if (len > 8192) return false
        if (len <= 8) {
            if (isRequest) {
                for (k in i until n) {
                    val c = (b[k].toInt() and 0xff).toChar()
                    if (c == ' ') return if (k == i) false else null
                    if (!isTokenChar(c)) return false
                }
            } else {
                val pfx = "HTTP/1."
                for (k in 0 until minOf(len, pfx.length)) if ((b[i + k].toInt() and 0xff).toChar() != pfx[k]) return false
            }
        }
        return null
    }

    private fun looksLikeH2(): Boolean {
        val b = acc.view(); val n = acc.size()
        val pfx = "PRI "
        if (n < 1) return false
        for (k in 0 until minOf(n, pfx.length)) if ((b[k].toInt() and 0xff).toChar() != pfx[k]) return false
        return true
    }

    /**
     * Request framing a different upstream parser could read differently (request smuggling /
     * desync): Transfer-Encoding with Content-Length, any Transfer-Encoding other than exactly
     * `chunked`, a non-numeric or comma-listed Content-Length, obs-fold, a header name that is not
     * a token (e.g. `Transfer-Encoding :`), or CR / LF / NUL inside a header line. Returns why, or null.
     */
    private fun headerLineProblem(text: String): String? {
        val lines = text.trimStart('\r', '\n').removeSuffix("\r\n\r\n").split("\r\n")
        for (l in lines.drop(1)) {
            if (l.isEmpty()) continue
            if (l.any { it == '\r' || it == '\n' || it == '\u0000' }) return "CR/LF/NUL inside a header line"
            if (l[0] == ' ' || l[0] == '\t') return "obsolete header line folding"
            val name = l.substringBefore(':')
            if (name.isEmpty() || !name.all(::isTokenChar)) return "invalid header name '${name.take(40)}'"
        }
        return null
    }

    private fun ambiguousRequestFraming(head: HttpHead): String? {
        val te = head.headers.filter { it.first.equals("transfer-encoding", true) }
        val cl = head.headers.filter { it.first.equals("content-length", true) }
        if (te.isNotEmpty() && cl.isNotEmpty()) return "both Transfer-Encoding and Content-Length"
        if (te.isNotEmpty() && (te.size > 1 || !te[0].second.trim().equals("chunked", ignoreCase = true))) return "Transfer-Encoding '${te.joinToString { it.second }.take(60)}'"
        if (cl.any { v -> v.second.trim().let { it.isEmpty() || !it.all { c -> c in '0'..'9' } } }) return "Content-Length '${cl.joinToString { it.second }.take(60)}'"
        return null
    }

    private fun isTokenChar(c: Char) = c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c in "!#$%&'*+.^_`|~-"

    private fun endsWithBlankLine(): Boolean {
        val n = acc.size()
        if (n < 4) return false
        val b = acc.view()
        if (b[n - 1] != LF || b[n - 2] != CR || b[n - 3] != LF || b[n - 4] != CR) return false
        // Leading blank lines between messages are tolerated (RFC 9112 §2.2): not a head yet.
        for (i in 0 until n) if (b[i] != CR && b[i] != LF) return true
        acc.reset()
        return false
    }

    private fun endsWithCrlf(): Boolean {
        val n = acc.size()
        if (n < 2) return false
        val b = acc.view()
        return b[n - 1] == LF && b[n - 2] == CR
    }

    /** ByteArrayOutputStream exposing its internal buffer (no copy on every byte). */
    private class Acc : ByteArrayOutputStream() { fun view(): ByteArray = buf }

    companion object {
        private const val CR = '\r'.code.toByte()
        private const val LF = '\n'.code.toByte()
        const val REASON_HTTP2 = "HTTP/2"
        const val REASON_NOT_HTTP = "not HTTP/1.x"
        const val REASON_AMBIGUOUS = "ambiguous request framing"
        const val REASON_TOO_LARGE = "header block too large"
    }
}

/** A complete message from [parseHttpStream], with its byte span in the stream. */
class ParsedHttp(val head: HttpHead, val wire: ByteArray, val body: ByteArray, val start: Int, val end: Int, val complete: Boolean)

/**
 * Parse a whole captured stream (one direction) into messages. For responses [methods] gives the
 * request method per index (HEAD responses have no body).
 */
fun parseHttpStream(bytes: ByteArray, isRequest: Boolean, methods: List<String> = emptyList()): List<ParsedHttp> {
    val out = ArrayList<ParsedHttp>()
    val parser = HttpStreamParser(isRequest, { methods.getOrNull(out.size) })
    var offset = 0
    var head: HttpHead? = null
    var start = 0
    val wire = ByteArrayOutputStream()
    val body = ByteArrayOutputStream()
    fun handle(events: List<HttpEvent>) {
        for (e in events) {
            when (e) {
                is HttpEvent.Head -> if (!e.interim) { head = e.head; start = offset; wire.reset(); body.reset(); wire.write(e.wire) }
                is HttpEvent.Body -> { wire.write(e.wire); body.write(e.data) }
                HttpEvent.End -> head?.let {
                    out += ParsedHttp(it, wire.toByteArray(), body.toByteArray(), start, offset, true); head = null
                }
                is HttpEvent.Raw -> {}
            }
            offset += e.wire.size
        }
    }
    handle(parser.feed(bytes))
    handle(parser.finish().filter { it !is HttpEvent.Raw })
    head?.let { out += ParsedHttp(it, wire.toByteArray(), body.toByteArray(), start, offset, false) }
    return out
}
