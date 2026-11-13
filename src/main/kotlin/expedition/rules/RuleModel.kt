package expedition.rules

import java.io.File

/** Which message a rule's matcher is evaluated against. */
enum class RuleDirection { REQUEST, RESPONSE }

/** Where a body comes from: literal text (UTF-8), hex bytes, or a file read when used. */
sealed class BodySource {
    abstract fun bytes(): ByteArray

    data class Text(val text: String) : BodySource() {
        override fun bytes() = text.toByteArray(Charsets.UTF_8)
    }

    data class Hex(val hex: String) : BodySource() {
        init { decode(hex) }
        override fun bytes() = decode(hex)
        companion object {
            fun decode(hex: String): ByteArray {
                val clean = hex.filterNot { it.isWhitespace() }
                require(clean.length % 2 == 0 && clean.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) { "invalid hex body" }
                return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            }
        }
    }

    /**
     * Body read from a file inside the rules-files sandbox ([RuleFiles.dir], by default
     * `~/.expedition/rules-files`). The file is validated and read ONCE when the rule is
     * created/updated/restored ([load]); serving a response never touches the disk. Equality is
     * by [path] only.
     */
    class FromFile private constructor(val path: String, private val data: ByteArray) : BodySource() {
        override fun bytes(): ByteArray = data
        override fun equals(other: Any?) = other is FromFile && other.path == path
        override fun hashCode() = path.hashCode()
        override fun toString() = "FromFile(path=$path, ${data.size} bytes)"

        companion object {
            /** Resolves [path] in the sandbox and reads it; IllegalArgumentException when not allowed. */
            fun load(path: String, dir: File = RuleFiles.dir()): FromFile = FromFile(path, RuleFiles.read(path, dir))
        }
    }
}

/** The only directory `bodyFile` may read from, and the read itself (bounded, regular files only). */
object RuleFiles {
    const val MAX_BYTES = 16 * 1024 * 1024

    /** `-Dexpedition.rulesFilesDir` (tests) or `<expedition dir>/rules-files`. */
    fun dir(): File = System.getProperty("expedition.rulesFilesDir")?.takeIf { it.isNotBlank() }?.let(::File)
        ?: File(expedition.server.PathSandbox.defaultBase(), "rules-files")

    fun read(path: String, dir: File = dir()): ByteArray {
        val f = try { expedition.server.PathSandbox(dir).resolve(path) } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("bodyFile: ${e.message} (put body files in ${dir.path})")
        }
        val p = f.toPath()
        val attrs = try {
            java.nio.file.Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes::class.java, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        } catch (e: java.io.IOException) { throw IllegalArgumentException("bodyFile: cannot read ${f.path}") }
        // Devices (/dev/zero), FIFOs, sockets and directories are refused before opening them.
        require(attrs.isRegularFile) { "bodyFile: ${f.path} is not a regular file" }
        require(attrs.size() <= MAX_BYTES) { "bodyFile: ${f.path} is larger than $MAX_BYTES bytes" }
        val bytes = java.nio.file.Files.newInputStream(p, java.nio.file.LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(MAX_BYTES + 1) }
        require(bytes.size <= MAX_BYTES) { "bodyFile: ${f.path} is larger than $MAX_BYTES bytes" }
        return bytes
    }
}

data class HeaderMatch(val name: String, val valueRegex: String? = null) {
    internal val regex: Regex? by lazy { valueRegex?.let { Regex(it, RegexOption.IGNORE_CASE) } }
}

/**
 * Every non-null field must match (AND). Host is a case-insensitive glob (`*.example.com`), path
 * is an exact or glob match on the path without query, [pathRegex] is searched in path+query.
 * For [RuleDirection.RESPONSE] rules, [headers]/[bodyRegex]/[status] apply to the response; the
 * request fields (method/host/path) apply to the request it answers.
 */
data class RuleMatcher(
    val direction: RuleDirection = RuleDirection.REQUEST,
    val method: String? = null,
    val host: String? = null,
    val port: Int? = null,
    val path: String? = null,
    val pathRegex: String? = null,
    val headers: List<HeaderMatch> = emptyList(),
    val bodyRegex: String? = null,
    val status: Int? = null,
    val listener: String? = null,
    val connectionId: Long? = null,
) {
    internal val pathRe: Regex? by lazy { pathRegex?.let { Regex(it) } }
    internal val bodyRe: Regex? by lazy { bodyRegex?.let { Regex(it, setOf(RegexOption.DOT_MATCHES_ALL)) } }
    internal val hostRe: Regex? by lazy { host?.let { globToRegex(it, ignoreCase = true) } }
    internal val pathGlob: Regex? by lazy { path?.let { globToRegex(it, ignoreCase = false) } }

    fun validate() {
        pathRe; bodyRe; headers.forEach { it.regex }
        port?.let { require(it in 1..65535) { "port must be 1-65535" } }
        status?.let { require(it in 100..999) { "status must be 100-999" } }
    }

    /** Matches everything except the body (decidable as soon as the header block is known). */
    fun matchesHead(ctx: MatchContext): Boolean {
        if (listener != null && !listener.equals(ctx.listener, ignoreCase = true)) return false
        if (connectionId != null && connectionId != ctx.connectionId) return false
        if (port != null && port != ctx.port) return false
        val req = ctx.request
        if (method != null && method.split('|', ',').none { it.trim().equals(req.method, ignoreCase = true) }) return false
        if (hostRe != null && !hostRe!!.matches(ctx.host)) return false
        if (pathGlob != null && !pathGlob!!.matches(req.path)) return false
        if (pathRe != null && !SafeRegex.containsMatch(pathRe!!, req.originTarget)) return false
        val subject = if (direction == RuleDirection.RESPONSE) ctx.response ?: return false else req
        if (status != null && (direction != RuleDirection.RESPONSE || subject.status != status)) return false
        for (h in headers) {
            val v = subject.header(h.name) ?: return false
            val re = h.regex
            if (re != null && !SafeRegex.containsMatch(re, v)) return false
        }
        return true
    }

    fun matches(ctx: MatchContext): Boolean {
        if (!matchesHead(ctx)) return false
        val re = bodyRe ?: return true
        val body = (if (direction == RuleDirection.RESPONSE) ctx.responseBody else ctx.requestBody) ?: return false
        val n = minOf(body.size, MAX_BODY_MATCH)
        return SafeRegex.containsMatch(re, String(body, 0, n, Charsets.ISO_8859_1))
    }

    val hasBodyMatcher: Boolean get() = bodyRegex != null

    companion object {
        const val MAX_BODY_MATCH = 1 shl 20

        fun globToRegex(glob: String, ignoreCase: Boolean): Regex {
            val sb = StringBuilder()
            glob.forEach { c ->
                when (c) {
                    '*' -> sb.append(".*")
                    '?' -> sb.append('.')
                    else -> sb.append(Regex.escape(c.toString()))
                }
            }
            return if (ignoreCase) Regex(sb.toString(), RegexOption.IGNORE_CASE) else Regex(sb.toString())
        }
    }
}

/** What a matcher is evaluated against. */
class MatchContext(
    val listener: String,
    val connectionId: Long,
    val upstreamHost: String,
    val port: Int,
    val request: HttpHead,
    val requestBody: ByteArray?,
    val response: HttpHead? = null,
    val responseBody: ByteArray? = null,
) {
    val host: String get() = request.host ?: upstreamHost
}

/** Header names/values written by rules must not be able to inject header lines or requests. */
object HeaderSafety {
    private val TOKEN = Regex("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

    fun requireSafe(name: String, value: String) {
        require(TOKEN.matches(name)) { "invalid header name '${name.take(40)}'" }
        require(value.none { it == '\r' || it == '\n' || it == '\u0000' }) { "header '$name' value must not contain CR, LF or NUL" }
    }
}

/** Header/body rewrite used by [RuleAction.TransformRequest] / [RuleAction.TransformResponse]. */
data class Transform(
    val setHeaders: List<Pair<String, String>> = emptyList(),
    val removeHeaders: List<String> = emptyList(),
    val replaceBody: BodySource? = null,
    /** Regex -> replacement pairs applied to the (de-chunked, decoded) body as ISO-8859-1 text. */
    val bodyReplace: List<Pair<String, String>> = emptyList(),
    /** Request only: regex -> replacement applied to the request target (path+query). */
    val urlReplace: Pair<String, String>? = null,
    /** Response only: replace the status code. */
    val status: Int? = null,
) {
    internal val bodyRes: List<Pair<Regex, String>> by lazy { bodyReplace.map { Regex(it.first) to it.second } }
    internal val urlRe: Pair<Regex, String>? by lazy { urlReplace?.let { Regex(it.first) to it.second } }
    fun validate() {
        bodyRes; urlRe; status?.let { require(it in 100..999) { "status must be 100-999" } }
        setHeaders.forEach { (n, v) -> HeaderSafety.requireSafe(n, v) }
        removeHeaders.forEach { HeaderSafety.requireSafe(it, "") }
    }
    val touchesBody: Boolean get() = replaceBody != null || bodyReplace.isNotEmpty()
}

sealed class RuleAction {
    /** Ends rule evaluation for the message (the request/response is answered or dropped). */
    open val terminal: Boolean get() = false

    data class MockResponse(
        val status: Int = 200,
        val reason: String? = null,
        val headers: List<Pair<String, String>> = emptyList(),
        val body: BodySource = BodySource.Text(""),
    ) : RuleAction() {
        override val terminal get() = true
        /** Wire form with a Content-Length body; [forHead] (answer to a HEAD request) omits the body bytes. */
        fun toBytes(forHead: Boolean = false): ByteArray {
            val head = HttpHead("HTTP/1.1 $status ${reason ?: defaultReason(status)}".trimEnd(), headers)
            val b = body.bytes()
            return if (forHead) head.remove("Transfer-Encoding").set("Content-Length", b.size.toString()).toBytes() else head.withBody(b)
        }
    }

    data class TransformRequest(val transform: Transform) : RuleAction()
    data class TransformResponse(val transform: Transform) : RuleAction()

    /**
     * Send the request to another upstream (`http(s)://host:port`) instead of the original one.
     * Authorization / Cookie / Proxy-Authorization are only sent to a DIFFERENT host:port when
     * [forwardCredentials] is set; the target's TLS certificate is verified unless [insecureTls].
     */
    data class Redirect(
        val url: String,
        val keepHost: Boolean = false,
        val forwardCredentials: Boolean = false,
        val insecureTls: Boolean = false,
    ) : RuleAction() {
        override val terminal get() = true
        init {
            val u = java.net.URI(url)
            require(u.scheme?.lowercase() in setOf("http", "https") && !u.host.isNullOrEmpty()) { "redirect url must be http(s)://host[:port]" }
        }
    }

    /** Wait [ms] (+ random 0..[jitterMs]) before continuing. */
    data class Delay(val ms: Long, val jitterMs: Long = 0) : RuleAction() {
        init { require(ms >= 0 && jitterMs >= 0 && ms + jitterMs <= 600_000) { "delay must be 0..600000 ms" } }
    }

    /** Never answer: the connection stays open and silent. */
    data object Timeout : RuleAction() { override val terminal get() = true }
    data object Close : RuleAction() { override val terminal get() = true }
    /** Close with a TCP RST (SO_LINGER 0). */
    data object Reset : RuleAction() { override val terminal get() = true }
    data object PassThrough : RuleAction() { override val terminal get() = true }

    /** Hold the request and/or response in Intercept even when intercept is off. */
    data class Breakpoint(val request: Boolean = true, val response: Boolean = false) : RuleAction()

    /**
     * POST a JSON description of the message to [url] (only when webhooks are enabled on the
     * engine). With [respond], a JSON reply `{status, headers, body|bodyHex}` becomes the response.
     */
    /**
     * Targets resolving to loopback / link-local (cloud metadata) / unique-local addresses are
     * refused unless [allowLocal]; credential headers are redacted from the payload unless
     * [forwardCredentials]; TLS certificates are verified unless [insecureTls].
     */
    data class Webhook(
        val url: String,
        val respond: Boolean = false,
        val allowLocal: Boolean = false,
        val forwardCredentials: Boolean = false,
        val insecureTls: Boolean = false,
    ) : RuleAction() {
        init {
            val u = java.net.URI(url)
            require(u.scheme?.lowercase() in setOf("http", "https") && !u.host.isNullOrEmpty()) { "webhook url must be http(s)://..." }
        }
    }

    companion object {
        fun defaultReason(status: Int): String = when (status) {
            200 -> "OK"; 201 -> "Created"; 202 -> "Accepted"; 204 -> "No Content"
            301 -> "Moved Permanently"; 302 -> "Found"; 304 -> "Not Modified"; 307 -> "Temporary Redirect"
            400 -> "Bad Request"; 401 -> "Unauthorized"; 403 -> "Forbidden"; 404 -> "Not Found"
            405 -> "Method Not Allowed"; 409 -> "Conflict"; 429 -> "Too Many Requests"
            500 -> "Internal Server Error"; 502 -> "Bad Gateway"; 503 -> "Service Unavailable"; 504 -> "Gateway Timeout"
            else -> ""
        }
    }
}

/**
 * An ordered, declarative rule. Actions run in order; a non-terminal-only rule (e.g. just a
 * transform or delay) lets evaluation continue with the next matching rule (chaining). [times]
 * limits how many messages the rule may handle (null = unlimited).
 */
data class HttpRule(
    val id: Long = 0,
    val name: String = "",
    val enabled: Boolean = true,
    val matcher: RuleMatcher = RuleMatcher(),
    val actions: List<RuleAction> = listOf(RuleAction.PassThrough),
    val times: Int? = null,
) {
    fun validate() {
        matcher.validate()
        times?.let { require(it >= 1) { "times must be >= 1" } }
        actions.forEach { a ->
            when (a) {
                is RuleAction.TransformRequest -> a.transform.validate()
                is RuleAction.TransformResponse -> a.transform.validate()
                is RuleAction.MockResponse -> {
                    a.headers.forEach { (n, v) -> HeaderSafety.requireSafe(n, v) }
                    a.reason?.let { r -> require(r.none { it == '\r' || it == '\n' || it == '\u0000' }) { "reason must not contain CR, LF or NUL" } }
                }
                else -> {}
            }
        }
    }

    val label: String get() = name.ifBlank { "rule #$id" }
}

/** Regex evaluation with a hard step budget so attacker-controlled bytes cannot ReDoS a worker. */
object SafeRegex {
    private class Budget : RuntimeException(null, null, false, false)

    private class Counting(private val s: CharSequence, private val budget: Long, private val c: LongArray) : CharSequence {
        override val length get() = s.length
        override fun get(index: Int): Char { if (++c[0] > budget) throw Budget(); return s[index] }
        override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = Counting(s.subSequence(startIndex, endIndex), budget, c)
        override fun toString() = s.toString()
    }

    /** Absolute ceiling on char reads per application (~sub-second), regardless of input size. */
    const val MAX_STEPS = 30_000_000L

    internal fun budget(len: Int) = minOf(MAX_STEPS, maxOf(5_000_000L, len * 4_000L))

    fun containsMatch(re: Regex, text: String): Boolean =
        try { re.containsMatchIn(Counting(text, budget(text.length), LongArray(1))) } catch (_: Budget) { false } catch (_: Exception) { false }

    /** Replace all; on budget exhaustion or error returns [text] unchanged. */
    fun replace(re: Regex, text: String, replacement: String): String =
        try { re.replace(Counting(text, budget(text.length), LongArray(1)), replacement) } catch (_: Budget) { text } catch (_: Exception) { text }
}
