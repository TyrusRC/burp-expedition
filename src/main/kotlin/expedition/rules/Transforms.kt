package expedition.rules

import expedition.analysis.HttpExchanges
import expedition.analysis.HttpMsg
import expedition.registry.ProxyMessage
import expedition.server.Json
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/** Header/body rewriting shared by request and response transforms. */
internal object Transforms {
    /** gzip/deflate-decoded body, or null when not encoded / not decodable. */
    fun decoded(head: HttpHead, body: ByteArray): ByteArray? {
        val enc = head.header("content-encoding")?.trim()?.lowercase()
        if (enc.isNullOrEmpty() || enc == "identity") return null
        return HttpExchanges.decodedBody(HttpMsg(head.startLine, head.headers, body, false))
    }

    fun apply(head0: HttpHead, body0: ByteArray, t: Transform): Pair<HttpHead, ByteArray> {
        var head = head0
        var body = body0
        t.status?.let { st ->
            if (head.isResponse) head = head.withStartLine("${head.version} $st ${RuleAction.defaultReason(st)}".trimEnd())
        }
        t.removeHeaders.forEach { head = head.remove(it) }
        t.setHeaders.forEach { (n, v) -> head = head.set(n, v) }
        if (t.touchesBody) {
            decoded(head, body)?.let { body = it; head = head.remove("Content-Encoding") }
            t.replaceBody?.let { body = it.bytes() }
            if (t.bodyRes.isNotEmpty()) {
                var text = String(body, Charsets.ISO_8859_1)
                t.bodyRes.forEach { (re, with) -> text = SafeRegex.replace(re, text, with) }
                body = text.toByteArray(Charsets.ISO_8859_1)
            }
        }
        return head to body
    }

    /** Request with a Content-Length body; a body-less request without framing headers stays without one. */
    fun serializeRequest(head: HttpHead, body: ByteArray, force: Boolean = false): ByteArray {
        val framed = head.has("content-length") || head.has("transfer-encoding")
        return if (body.isEmpty() && !framed && !force) head.toBytes() else head.withBody(body)
    }
}

/**
 * Minimal blocking HTTP/1.1 client for redirect targets and webhooks. TLS certificates (and the
 * host name) are verified unless the caller passes `insecure = true` (explicit rule flag).
 */
object OutboundHttp {
    class Response(val head: HttpHead, val body: ByteArray)

    private val trustAll: SSLSocketFactory by lazy {
        val tm = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }.socketFactory
    }

    /** True for addresses a webhook must not reach by default (SSRF): loopback, link-local/metadata, ULA, any-local. */
    fun isLocalAddress(a: InetAddress): Boolean {
        if (a.isLoopbackAddress || a.isLinkLocalAddress || a.isAnyLocalAddress) return true
        val b = a.address
        if (a is Inet6Address) {
            if ((b[0].toInt() and 0xfe) == 0xfc) return true                      // fc00::/7
            // IPv4-mapped / compatible forms of a local v4 address
            if (b.copyOfRange(0, 10).all { it == 0.toByte() } && (b[10] == 0xff.toByte() && b[11] == 0xff.toByte() || b[10] == 0.toByte() && b[11] == 0.toByte())) {
                val v4 = runCatching { InetAddress.getByAddress(b.copyOfRange(12, 16)) }.getOrNull()
                if (v4 != null && !(b[10] == 0.toByte() && v4.address.all { it == 0.toByte() })) return isLocalAddress(v4)
            }
            return false
        }
        val o0 = b[0].toInt() and 0xff; val o1 = b[1].toInt() and 0xff
        return o0 == 127 || o0 == 0 || (o0 == 169 && o1 == 254) || (o0 == 100 && o1 == 100 && (b[2].toInt() and 0xff) == 100 && (b[3].toInt() and 0xff) == 200)
    }

    /**
     * Sends [request] to [url]. The host is resolved ONCE and that address is used for the
     * connection (no DNS-rebinding window); with [blockLocal] a local address is refused.
     */
    fun send(url: URI, request: ByteArray, method: String, timeoutMs: Int = 15_000, insecure: Boolean = false, blockLocal: Boolean = false): Response {
        val https = url.scheme.equals("https", ignoreCase = true)
        val port = if (url.port > 0) url.port else if (https) 443 else 80
        val host = url.host.removePrefix("[").removeSuffix("]")
        val addrs = InetAddress.getAllByName(host)
        if (blockLocal) addrs.firstOrNull(::isLocalAddress)?.let {
            throw IOException("refusing to connect to local address ${it.hostAddress} (set allowLocal to permit)")
        }
        val plain = Socket().apply { connect(InetSocketAddress(addrs.first(), port), timeoutMs); soTimeout = timeoutMs }
        val sock = if (!https) plain else {
            val factory = if (insecure) trustAll else SSLSocketFactory.getDefault() as SSLSocketFactory
            (factory.createSocket(plain, host, port, true) as SSLSocket).apply {
                if (!insecure) sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                startHandshake()
            }
        }
        sock.use { s ->
            s.getOutputStream().apply { write(request); flush() }
            val parser = HttpStreamParser(false, { method })
            var head: HttpHead? = null
            val body = ByteArrayOutputStream()
            var done = false
            fun handle(events: List<HttpEvent>) {
                for (e in events) when (e) {
                    is HttpEvent.Head -> if (!e.interim) head = e.head
                    is HttpEvent.Body -> body.write(e.data)
                    HttpEvent.End -> done = true
                    is HttpEvent.Raw -> throw IOException("upstream reply is not HTTP/1.x")
                }
            }
            val buf = ByteArray(16 * 1024)
            val input = s.getInputStream()
            while (!done) {
                val n = input.read(buf)
                if (n < 0) { handle(parser.finish().filter { it !is HttpEvent.Raw }); break }
                handle(parser.feed(buf.copyOf(n)))
                if (body.size() > 64 * 1024 * 1024) throw IOException("response too large")
            }
            return Response(head ?: throw IOException("no HTTP response"), body.toByteArray())
        }
    }

    /** Re-frame for relaying on the client's keep-alive connection: Content-Length, no hop-by-hop headers. */
    fun normalized(r: Response, method: String): ByteArray {
        val h = r.head.remove("Connection").remove("Keep-Alive").remove("Transfer-Encoding")
        val noBody = method.equals("HEAD", true) || r.head.status == 204 || r.head.status == 304
        return if (noBody) h.toBytes() else h.withBody(r.body)
    }

    fun postJson(url: String, json: String, timeoutMs: Int = 10_000, insecure: Boolean = false, blockLocal: Boolean = true): Response {
        val u = URI(url)
        val body = json.toByteArray(Charsets.UTF_8)
        val target = (u.rawPath?.ifEmpty { "/" } ?: "/") + (u.rawQuery?.let { "?$it" } ?: "")
        val head = HttpHead("POST $target HTTP/1.1", listOf(
            "Host" to u.rawAuthority, "Content-Type" to "application/json", "Connection" to "close",
            "User-Agent" to "expedition-rules",
        ))
        return send(u, head.withBody(body), "POST", timeoutMs, insecure, blockLocal)
    }
}

/** Webhook / callback actions. */
internal object Webhooks {
    private const val MAX_BODY = 64 * 1024
    val CREDENTIAL_HEADERS = setOf("authorization", "cookie", "proxy-authorization")

    fun payload(
        rule: HttpRule, phase: String, connectionId: Long, control: ConnectionControl,
        request: HttpHead, requestBody: ByteArray?, response: HttpHead?, responseBody: ByteArray?,
        keepCredentials: Boolean = false,
    ): String {
        val host = request.host ?: control.upstreamHost
        val o = linkedMapOf<String, Any?>(
            "rule" to rule.label, "ruleId" to rule.id, "phase" to phase,
            "connectionId" to connectionId, "listener" to control.listenerName,
            "method" to request.method, "host" to host, "port" to control.upstreamPort,
            "path" to request.path, "target" to request.originTarget,
            "requestHeaders" to redact(request.headers, keepCredentials).map { listOf(it.first, it.second) },
        )
        requestBody?.let { o["requestBody"] = text(it) }
        response?.let {
            o["status"] = it.status
            o["responseHeaders"] = redact(it.headers, keepCredentials).map { h -> listOf(h.first, h.second) }
        }
        responseBody?.let { o["responseBody"] = text(it) }
        return Json.obj(o)
    }

    private fun text(b: ByteArray) = String(b, 0, minOf(b.size, MAX_BODY), Charsets.UTF_8)

    /** Credential headers (Authorization, Cookie, Set-Cookie, Proxy-Authorization) have their value replaced. */
    fun redact(headers: List<Pair<String, String>>, keep: Boolean): List<Pair<String, String>> =
        if (keep) headers else headers.map { if (it.first.lowercase() in CREDENTIAL_HEADERS || it.first.equals("set-cookie", true)) it.first to "[redacted]" else it }

    fun fire(a: RuleAction.Webhook, payload: String) {
        RuleExecutors.io.execute { runCatching { OutboundHttp.postJson(a.url, payload, insecure = a.insecureTls, blockLocal = !a.allowLocal) } }
    }

    /** Blocking call; a JSON reply with a numeric `status` becomes a mock response, anything else null. */
    fun call(a: RuleAction.Webhook, payload: String): RuleAction.MockResponse? = try {
        val r = OutboundHttp.postJson(a.url, payload, insecure = a.insecureTls, blockLocal = !a.allowLocal)
        // A callback reply may not name local files (bodyFile).
        val o = Json.asObject(Json.parse(String(r.body, Charsets.UTF_8).ifBlank { "{}" })) - "bodyFile"
        if (r.head.status in 200..299 && o["status"] is Number)
            (RuleCodec.actionFromMap(o + ("type" to "mock")) as RuleAction.MockResponse).also { m ->
                HttpRule(actions = listOf(m)).validate() // no CR/LF/NUL injected through headers / reason
            }
        else null
    } catch (_: Exception) { null }
}

/** "Create rule from traffic": turn a recorded exchange into a matcher + mock rule. */
object RuleFromTraffic {
    class Exchange(val index: Int, val request: ParsedHttp, val response: ParsedHttp?) {
        val label: String get() = "#$index ${request.head.method} ${request.head.originTarget}" +
            (response?.let { " -> ${it.head.status}" } ?: " (no response)")
    }

    private val HOP = setOf("content-length", "transfer-encoding", "connection", "keep-alive", "date")

    fun exchanges(messages: List<ProxyMessage>): List<Exchange> {
        val up = ByteArrayOutputStream(); val down = ByteArrayOutputStream()
        for (m in messages) if (!m.isNote) (if (m.direction == expedition.registry.Direction.CLIENT_TO_UPSTREAM) up else down).write(m.rawBytes)
        val reqs = parseHttpStream(up.toByteArray(), true)
        val resps = parseHttpStream(down.toByteArray(), false, reqs.map { it.head.method })
        return reqs.mapIndexed { i, r -> Exchange(i, r, resps.getOrNull(i)) }
    }

    /** Index of the exchange containing [messageId] (by byte offset in its direction's stream), or null. */
    fun exchangeIndexFor(messages: List<ProxyMessage>, exchanges: List<Exchange>, messageId: Long): Int? {
        val m = messages.firstOrNull { it.id == messageId }?.takeUnless { it.isNote } ?: return null
        val offset = messages.takeWhile { it.id != messageId }.filter { it.direction == m.direction && !it.isNote }.sumOf { it.rawBytes.size }
        val req = m.direction == expedition.registry.Direction.CLIENT_TO_UPSTREAM
        return exchanges.indexOfFirst { e ->
            val p = if (req) e.request else e.response ?: return@indexOfFirst false
            offset >= p.start && offset < maxOf(p.end, p.start + 1)
        }.takeIf { it >= 0 }
    }

    fun build(exchange: Exchange, connectionId: Long? = null): HttpRule {
        val req = exchange.request.head
        val matcher = RuleMatcher(method = req.method, host = req.host, path = req.path)
        val resp = exchange.response
        val action: RuleAction = if (resp == null) RuleAction.PassThrough else {
            val body = resp.body
            val utf8 = runCatching {
                Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(body)).toString()
            }.getOrNull()
            val src = if (utf8 != null && utf8.none { it < ' ' && it !in "\r\n\t" }) BodySource.Text(utf8)
                else BodySource.Hex(body.joinToString("") { "%02x".format(it) })
            RuleAction.MockResponse(
                status = resp.head.status, reason = resp.head.reason.ifEmpty { null },
                headers = resp.head.headers.filterNot { it.first.lowercase() in HOP },
                body = src,
            )
        }
        val suffix = connectionId?.let { " (conn $it)" } ?: ""
        return HttpRule(name = "${req.method} ${req.path}$suffix", matcher = matcher, actions = listOf(action))
    }

    /**
     * Builds a rule from connection traffic: the exchange holding [messageId], else exchange
     * [index], else the last exchange that has a response.
     */
    fun fromConnection(messages: List<ProxyMessage>, connectionId: Long, messageId: Long? = null, index: Int? = null): HttpRule {
        val ex = exchanges(messages)
        require(ex.isNotEmpty()) { "no HTTP/1.x request found in connection $connectionId" }
        val i = when {
            messageId != null -> exchangeIndexFor(messages, ex, messageId)
                ?: throw IllegalArgumentException("message $messageId is not part of an HTTP exchange in connection $connectionId")
            index != null -> index.also { require(it in ex.indices) { "index out of range (0..${ex.size - 1})" } }
            else -> ex.indexOfLast { it.response != null }.takeIf { it >= 0 } ?: ex.size - 1
        }
        return build(ex[i], connectionId)
    }
}
