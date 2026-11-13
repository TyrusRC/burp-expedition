package expedition.export

import expedition.analysis.HttpExchanges
import expedition.analysis.HttpMsg
import expedition.registry.ConnectionRegistry
import expedition.registry.ConnectionSummary
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.registry.ProxyMessage
import expedition.server.Json
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.time.Instant
import java.util.Base64
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPOutputStream

/** Result of [HarCodec.export]. [skippedConnections] = connections with no parseable HTTP/1.x exchange. */
data class HarExport(val json: String, val entries: Int, val skippedConnections: Int)

/** Result of [HarCodec.import]. [skippedEntries] = HAR entries that could not be turned into a request. */
data class HarImport(val entries: Int, val connectionsAdded: Int, val messagesAdded: Int, val skippedEntries: Int)

/** HAR 1.2 export of HTTP/1.x traffic in a [ConnectionRegistry] and import back into raw request/response messages. */
object HarCodec {
    private const val CREATOR = "Burp Expedition"

    // ── Export ──────────────────────────────────────────────────────────

    fun export(registry: ConnectionRegistry, connectionId: Long? = null): HarExport {
        val conns = if (connectionId != null)
            listOf(registry.connection(connectionId) ?: throw IllegalArgumentException("unknown connection $connectionId"))
        else registry.allConnections()
        val entries = ArrayList<Pair<Instant, Map<String, Any?>>>()
        var skipped = 0
        for (c in conns) {
            if (c.protocol != Protocol.TCP) { skipped++; continue }
            val msgs = registry.messagesFor(c.connectionId)
            val exchanges = HttpExchanges.extract(c.connectionId, msgs)
            if (exchanges.isEmpty()) { skipped++; continue }
            val start = msgs.firstOrNull { it.direction == Direction.CLIENT_TO_UPSTREAM }?.timestamp ?: c.openedAt
            val firstResp = msgs.firstOrNull { it.direction == Direction.UPSTREAM_TO_CLIENT }?.timestamp
            val wait = if (firstResp != null) maxOf(0L, firstResp.toEpochMilli() - start.toEpochMilli()) else 0L
            for (x in exchanges) entries.add(start to entry(c, x.request, x.response, start, wait))
        }
        val sorted = entries.sortedBy { it.first }.map { it.second }
        val log = mapOf(
            "version" to "1.2",
            "creator" to mapOf("name" to CREATOR, "version" to expedition.BuildInfo.VERSION),
            "entries" to sorted,
        )
        return HarExport(Json.obj("log" to log), sorted.size, skipped)
    }

    private fun entry(c: ConnectionSummary, req: HttpMsg, res: HttpMsg?, start: Instant, wait: Long): Map<String, Any?> {
        val url = urlOf(c, req)
        val e = LinkedHashMap<String, Any?>()
        e["startedDateTime"] = start.toString()
        e["time"] = wait
        e["request"] = requestObj(req, url)
        e["response"] = res?.let { responseObj(it) } ?: emptyResponse()
        e["cache"] = emptyMap<String, Any?>()
        e["timings"] = mapOf("send" to 0, "wait" to wait, "receive" to 0)
        e["connection"] = c.connectionId.toString()
        hostOnly(c.upstreamAddress)?.let { e["serverIPAddress"] = it }
        return e
    }

    internal fun urlOf(c: ConnectionSummary, req: HttpMsg): String {
        val t = req.target
        if (t.startsWith("http://") || t.startsWith("https://")) return t
        val port = c.upstreamAddress.substringAfterLast(':', "").toIntOrNull()
        val scheme = if (c.tls || port == 443 || port == 8443) "https" else "http"
        val host = req.header("host") ?: c.upstreamAddress
        return "$scheme://$host$t"
    }

    private fun hostOnly(addr: String): String? {
        val h = addr.substringBeforeLast(':').removePrefix("[").removeSuffix("]")
        return h.takeIf { it.isNotEmpty() }
    }

    private fun version(startLine: String, response: Boolean): String =
        if (response) startLine.substringBefore(' ') else startLine.substringAfterLast(' ')

    private fun headerList(h: List<Pair<String, String>>) = h.map { mapOf("name" to it.first, "value" to it.second) }

    private fun requestObj(req: HttpMsg, url: String): Map<String, Any?> {
        val o = LinkedHashMap<String, Any?>()
        o["method"] = req.method
        o["url"] = url
        o["httpVersion"] = version(req.startLine, false)
        o["cookies"] = parseCookieHeader(req.header("cookie"))
        o["headers"] = headerList(req.headers)
        o["queryString"] = parseQuery(url)
        if (req.body.isNotEmpty()) {
            val p = LinkedHashMap<String, Any?>()
            p["mimeType"] = req.header("content-type") ?: ""
            val s = strictUtf8(req.body)
            if (s != null) p["text"] = s else { p["text"] = b64(req.body); p["_encoding"] = "base64" }
            o["postData"] = p
        }
        o["headersSize"] = -1
        o["bodySize"] = req.body.size
        return o
    }

    private fun responseObj(res: HttpMsg): Map<String, Any?> {
        val decoded = HttpExchanges.decodedBody(res)
        val content = LinkedHashMap<String, Any?>()
        val shown = decoded ?: res.body
        content["size"] = shown.size
        if (decoded != null && decoded.size > res.body.size) content["compression"] = decoded.size - res.body.size
        content["mimeType"] = res.header("content-type") ?: ""
        if (shown.isNotEmpty()) {
            val s = if (decoded != null) strictUtf8(shown) else null
            if (s != null) content["text"] = s else { content["text"] = b64(shown); content["encoding"] = "base64" }
        }
        if (decoded == null && res.body.isNotEmpty()) content["_wireEncoded"] = true
        val o = LinkedHashMap<String, Any?>()
        o["status"] = res.status
        o["statusText"] = res.startLine.split(' ', limit = 3).getOrElse(2) { "" }
        o["httpVersion"] = version(res.startLine, true)
        o["cookies"] = res.headers.filter { it.first.equals("set-cookie", true) }.map { parseSetCookie(it.second) }
        o["headers"] = headerList(res.headers)
        o["content"] = content
        o["redirectURL"] = res.header("location") ?: ""
        o["headersSize"] = -1
        o["bodySize"] = res.body.size
        return o
    }

    private fun emptyResponse() = mapOf(
        "status" to 0, "statusText" to "", "httpVersion" to "HTTP/1.1", "cookies" to emptyList<Any>(),
        "headers" to emptyList<Any>(), "content" to mapOf("size" to 0, "mimeType" to ""),
        "redirectURL" to "", "headersSize" to -1, "bodySize" to -1,
    )

    private fun parseCookieHeader(v: String?): List<Map<String, Any?>> =
        if (v == null) emptyList() else v.split(';').map { it.trim() }.filter { it.isNotEmpty() }.map {
            mapOf("name" to it.substringBefore('='), "value" to it.substringAfter('=', ""))
        }

    private fun parseSetCookie(v: String): Map<String, Any?> {
        val parts = v.split(';').map { it.trim() }
        val m = LinkedHashMap<String, Any?>()
        m["name"] = parts[0].substringBefore('=')
        m["value"] = parts[0].substringAfter('=', "")
        for (a in parts.drop(1)) {
            when (a.substringBefore('=').lowercase()) {
                "path" -> m["path"] = a.substringAfter('=', "")
                "domain" -> m["domain"] = a.substringAfter('=', "")
                "httponly" -> m["httpOnly"] = true
                "secure" -> m["secure"] = true
            }
        }
        return m
    }

    internal fun parseQuery(url: String): List<Map<String, Any?>> {
        val q = url.substringAfter('?', "").substringBefore('#')
        if (q.isEmpty()) return emptyList()
        return q.split('&').filter { it.isNotEmpty() }.map {
            mapOf("name" to dec(it.substringBefore('=')), "value" to dec(it.substringAfter('=', "")))
        }
    }

    private fun dec(s: String) = try { URLDecoder.decode(s, "UTF-8") } catch (_: Exception) { s }

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    /** The bytes as a String if they are valid UTF-8 without NULs, else null. */
    internal fun strictUtf8(b: ByteArray): String? {
        if (b.any { it == 0.toByte() }) return null
        return try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString()
        } catch (_: CharacterCodingException) { null }
    }

    // ── Import ──────────────────────────────────────────────────────────

    fun import(registry: ConnectionRegistry, harJson: String): HarImport {
        val root = try { Json.asObject(Json.parse(harJson)) } catch (e: Exception) {
            throw IllegalArgumentException("not valid JSON: ${e.message}")
        }
        val log = root["log"] as? Map<*, *> ?: throw IllegalArgumentException("not a HAR file: missing \"log\"")
        val list = log["entries"] as? List<*> ?: throw IllegalArgumentException("not a HAR file: missing \"log.entries\"")
        var nextConn = (registry.allConnections().maxOfOrNull { it.connectionId } ?: 0L) + 1
        var nextMsg = (registry.allMessages().maxOfOrNull { it.id } ?: 0L) + 1
        val conns = ArrayList<ConnectionSummary>()
        val msgs = ArrayList<ProxyMessage>()
        var skipped = 0
        for (item in list) {
            val e = Json.asObject(item)
            val built = try { buildEntry(e) } catch (_: Exception) { null }
            if (built == null) { skipped++; continue }
            val started = (e["startedDateTime"] as? String)?.let { runCatching { Instant.parse(it) }.getOrNull()
                ?: runCatching { java.time.OffsetDateTime.parse(it).toInstant() }.getOrNull() } ?: Instant.now()
            val id = nextConn++
            val ms = e["time"].let { (it as? Number)?.toLong() ?: 0L }.coerceIn(0L, 3_600_000L)
            conns.add(ConnectionSummary(id, "har-import", Protocol.TCP, "har", built.upstream, started, started.plusMillis(ms)))
            msgs.add(ProxyMessage(nextMsg++, id, Direction.CLIENT_TO_UPSTREAM, started, built.request))
            if (built.response != null)
                msgs.add(ProxyMessage(nextMsg++, id, Direction.UPSTREAM_TO_CLIENT, started.plusMillis(ms), built.response))
        }
        val r = registry.importSnapshot(conns, msgs)
        return HarImport(list.size - skipped, r.connectionsAdded, r.messagesAdded, skipped)
    }

    private class Built(val upstream: String, val request: ByteArray, val response: ByteArray?)

    private fun buildEntry(e: Map<String, Any?>): Built? {
        val req = Json.asObject(e["request"])
        val method = (req["method"] as? String)?.trim()?.uppercase().orEmpty()
        val url = req["url"] as? String ?: return null
        if (method.isEmpty() || !method.all { it.isLetter() || it == '-' }) return null
        val (scheme, authority, target) = splitUrl(url) ?: return null
        val (host, port) = splitAuthority(authority, scheme)
        if (host.isEmpty()) return null
        val upstream = "$host:$port"

        // Request
        val reqHeaders = readHeaders(req["headers"])
        val body = requestBody(req["postData"])
        val hdrs = ArrayList<Pair<String, String>>()
        var hasHost = false
        for ((n, v) in reqHeaders) {
            if (n.startsWith(":")) {
                if (n == ":authority" && reqHeaders.none { it.first.equals("host", true) } && !hasHost) { hdrs.add("Host" to v); hasHost = true }
                continue
            }
            if (n.equals("host", true)) hasHost = true
            if (n.equals("content-length", true) || n.equals("transfer-encoding", true)) continue
            hdrs.add(n to v)
        }
        if (!hasHost) hdrs.add(0, "Host" to authority)
        if (body.isNotEmpty() || method in setOf("POST", "PUT", "PATCH")) hdrs.add("Content-Length" to body.size.toString())
        val rawReq = serialize("$method $target ${httpVersion(req["httpVersion"])}", hdrs, body)

        // Response
        val res = Json.asObject(e["response"])
        val status = (res["status"] as? Number)?.toInt() ?: 0
        val rawRes = if (status !in 100..599) null else buildResponse(res, status, method)
        return Built(upstream, rawReq, rawRes)
    }

    private fun buildResponse(res: Map<String, Any?>, status: Int, method: String): ByteArray {
        val content = Json.asObject(res["content"])
        val headers = readHeaders(res["headers"]).filter { !it.first.startsWith(":") }
        val noBody = method == "HEAD" || status == 204 || status == 304 || status in 100..199
        val hdrs = ArrayList<Pair<String, String>>()
        var body = ByteArray(0)
        if (noBody) {
            hdrs.addAll(headers.filter { !it.first.equals("transfer-encoding", true) })
        } else {
            var decodedBody = contentBytes(content)
            val wire = content["_wireEncoded"] == true
            val enc = headers.firstOrNull { it.first.equals("content-encoding", true) }?.second?.trim()?.lowercase()
            var keepEnc = true
            if (!wire && enc != null && enc != "identity") {
                when (enc) {
                    "gzip", "x-gzip" -> decodedBody = ByteArrayOutputStream().also { o -> GZIPOutputStream(o).use { it.write(decodedBody) } }.toByteArray()
                    "deflate" -> decodedBody = ByteArrayOutputStream().also { o -> DeflaterOutputStream(o).use { it.write(decodedBody) } }.toByteArray()
                    else -> keepEnc = false // cannot re-encode (br, zstd, ...): ship the decoded body as identity
                }
            }
            body = decodedBody
            for (h in headers) {
                if (h.first.equals("content-length", true) || h.first.equals("transfer-encoding", true)) continue
                if (!keepEnc && h.first.equals("content-encoding", true)) continue
                hdrs.add(h)
            }
            hdrs.add("Content-Length" to body.size.toString())
        }
        val text = (res["statusText"] as? String)?.trim().orEmpty()
        val line = "${httpVersion(res["httpVersion"])} $status" + if (text.isNotEmpty()) " $text" else ""
        return serialize(line, hdrs, if (noBody) ByteArray(0) else body)
    }

    private fun contentBytes(content: Map<String, Any?>): ByteArray {
        val text = content["text"] as? String ?: return ByteArray(0)
        return if ((content["encoding"] as? String)?.lowercase() == "base64") Base64.getDecoder().decode(text)
        else text.toByteArray(Charsets.UTF_8)
    }

    private fun requestBody(postData: Any?): ByteArray {
        val p = Json.asObject(postData)
        val text = p["text"] as? String
        if (text != null) {
            return if ((p["_encoding"] as? String)?.lowercase() == "base64") Base64.getDecoder().decode(text)
            else text.toByteArray(Charsets.UTF_8)
        }
        val params = p["params"] as? List<*> ?: return ByteArray(0)
        return params.joinToString("&") {
            val o = Json.asObject(it)
            java.net.URLEncoder.encode(Json.str(o, "name"), "UTF-8") + "=" + java.net.URLEncoder.encode(Json.str(o, "value"), "UTF-8")
        }.toByteArray(Charsets.UTF_8)
    }

    private fun readHeaders(v: Any?): List<Pair<String, String>> = (v as? List<*>)?.mapNotNull {
        val o = Json.asObject(it)
        val n = o["name"] as? String ?: return@mapNotNull null
        n.trim() to (o["value"]?.toString() ?: "")
    }?.filter { validName(it.first) }
        ?.map { it.first to it.second.replace("\r", "").replace("\n", " ") } ?: emptyList()

    private fun validName(n: String) =
        n.isNotEmpty() && n.drop(1).none { it == ':' || it == ' ' || it == '\r' || it == '\n' } && n[0] != ' ' && n[0] != '\r' && n[0] != '\n'

    private fun httpVersion(v: Any?): String {
        val s = (v as? String)?.uppercase().orEmpty()
        return if (s == "HTTP/1.0") "HTTP/1.0" else "HTTP/1.1"
    }

    private fun serialize(startLine: String, headers: List<Pair<String, String>>, body: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        val head = StringBuilder(startLine).append("\r\n")
        for ((n, v) in headers) head.append(n).append(": ").append(v).append("\r\n")
        head.append("\r\n")
        o.write(head.toString().toByteArray(Charsets.ISO_8859_1))
        o.write(body)
        return o.toByteArray()
    }

    /** host (IPv6 keeps brackets) and port of an authority; port defaults from [scheme]. */
    internal fun splitAuthority(authority: String, scheme: String): Pair<String, Int> {
        val def = if (scheme == "https") 443 else 80
        if (authority.startsWith("[")) {
            val close = authority.indexOf(']')
            if (close < 0) return authority to def
            return authority.substring(0, close + 1) to (authority.substring(close + 1).removePrefix(":").toIntOrNull() ?: def)
        }
        val colon = authority.lastIndexOf(':')
        if (colon < 0) return authority to def
        return authority.substring(0, colon) to (authority.substring(colon + 1).toIntOrNull() ?: def)
    }

    /** scheme, authority, request-target(path+query) of an absolute http(s) URL; null if not one. */
    internal fun splitUrl(url: String): Triple<String, String, String>? {
        val m = Regex("^(https?)://([^/?#]+)([^#]*)", RegexOption.IGNORE_CASE).find(url.trim()) ?: return null
        val authority = m.groupValues[2].substringAfterLast('@')
        var target = m.groupValues[3]
        if (target.isEmpty()) target = "/" else if (target.startsWith("?")) target = "/$target"
        return Triple(m.groupValues[1].lowercase(), authority, target.replace(" ", "%20"))
    }
}
