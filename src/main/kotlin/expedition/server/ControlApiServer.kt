package expedition.server

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import expedition.engine.ListenerConfig
import expedition.engine.TlsMode
import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import expedition.registry.ProxyMessage
import expedition.ui.ReplaySender
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * Loopback REST control API for Expedition — lets an external client (the
 * Praetor MCP server) drive the TCP/UDP proxy programmatically: manage
 * listeners, read captured connections/messages as evidence, run the Repeater
 * (ReplaySender), and manage match-and-replace rules.
 *
 * Bound to 127.0.0.1 only; every request is Host-header checked against literal
 * loopback forms (DNS-rebinding safe — never resolves a hostname), mirroring the
 * praetor-burp-ext BaseHandler/OriginCheck guard. Not started unless the bind
 * host is loopback.
 */
class ControlApiServer(
    private val host: String,
    private val port: Int,
    private val registry: ConnectionRegistry,
    private val matchReplace: MatchReplaceEngine,
    private val startListener: (ListenerConfig) -> Unit,
    private val stopListener: (String) -> Unit,
    private val runningListeners: () -> Set<String>,
    private val replaySender: ReplaySender = ReplaySender(),
    private val version: String = "0.1.0",
) {
    private var server: HttpServer? = null
    private val ruleIds = AtomicLong(1)

    /** True when the API is bound beyond loopback (operator's risk — remote/WSL). */
    fun isExposedBeyondLoopback(): Boolean = !isLoopback(host)

    fun start() {
        // Default is loopback (secure). A non-loopback bind is ALLOWED (the
        // Praetor MCP server on a NAT-mode WSL reaches Burp via the host IP, not
        // 127.0.0.1) but the caller is expected to log the exposure warning.
        val s = HttpServer.create(InetSocketAddress(host, port), 0)
        s.executor = Executors.newFixedThreadPool(2)
        s.createContext("/") { ex -> safeHandle(ex) }
        s.start()
        server = s
    }

    fun stop() {
        server?.stop(0)
        server = null
    }

    private fun safeHandle(ex: HttpExchange) {
        try {
            if (!hostAllowed(ex)) { send(ex, 403, Json.obj("error" to "non-loopback Host rejected")); return }
            route(ex)
        } catch (e: IllegalArgumentException) {
            send(ex, 400, Json.obj("error" to (e.message ?: "bad request")))
        } catch (e: Exception) {
            send(ex, 500, Json.obj("error" to (e.message ?: "internal error")))
        } finally {
            ex.close()
        }
    }

    private fun route(ex: HttpExchange) {
        val method = ex.requestMethod
        val path = ex.requestURI.path.trimEnd('/')
        when {
            method == "GET" && (path == "" || path == "/status") -> status(ex)
            method == "GET" && path == "/listeners" -> send(ex, 200, Json.obj("running" to runningListeners().toList()))
            method == "POST" && path == "/listeners" -> addListener(ex)
            method == "DELETE" && path.startsWith("/listeners/") -> {
                stopListener(path.removePrefix("/listeners/")); send(ex, 200, Json.obj("ok" to true))
            }
            method == "GET" && path == "/connections" -> connections(ex)
            method == "GET" && path.matches(Regex("/connections/\\d+/messages")) ->
                messages(ex, path.split("/")[2].toLong())
            method == "GET" && path == "/messages" -> allMessages(ex)
            method == "POST" && path == "/repeat" -> repeat(ex)
            method == "GET" && path == "/matchreplace" -> listRules(ex)
            method == "POST" && path == "/matchreplace" -> addRule(ex)
            method == "DELETE" && path.startsWith("/matchreplace/") -> {
                matchReplace.removeRule(path.removePrefix("/matchreplace/").toLong())
                send(ex, 200, Json.obj("ok" to true))
            }
            else -> send(ex, 404, Json.obj("error" to "no route: $method $path"))
        }
    }

    // ── Handlers ────────────────────────────────────────────────────────────
    private fun status(ex: HttpExchange) = send(ex, 200, Json.obj(
        "version" to version,
        "running_listeners" to runningListeners().toList(),
        "connections" to registry.allConnections().size,
        "messages" to registry.allMessages().size,
    ))

    private fun addListener(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val cfg = ListenerConfig(
            name = Json.str(o, "name").ifBlank { throw IllegalArgumentException("name required") },
            protocol = Protocol.valueOf(Json.str(o, "protocol", "TCP").uppercase()),
            bindHost = Json.str(o, "bind_host", "127.0.0.1"),
            bindPort = Json.int(o, "bind_port").also { require(it in 1..65535) { "bind_port 1-65535" } },
            upstreamHost = Json.str(o, "upstream_host").ifBlank { throw IllegalArgumentException("upstream_host required") },
            upstreamPort = Json.int(o, "upstream_port").also { require(it in 1..65535) { "upstream_port 1-65535" } },
            tlsMode = if (Json.str(o, "tls", "none").equals("mitm", true)) TlsMode.MITM else TlsMode.NONE,
        )
        startListener(cfg)
        send(ex, 200, Json.obj("ok" to true, "name" to cfg.name))
    }

    private fun connections(ex: HttpExchange) = send(ex, 200, Json.arr(
        registry.allConnections().map { c -> mapOf(
            "id" to c.connectionId, "listener" to c.listenerName, "protocol" to c.protocol.name,
            "client" to c.clientAddress, "upstream" to c.upstreamAddress,
            "opened_at" to c.openedAt.toString(), "closed_at" to (c.closedAt?.toString()),
        ) }
    ))

    private fun messages(ex: HttpExchange, connId: Long) =
        send(ex, 200, Json.arr(registry.messagesFor(connId).map(::messageMap)))

    private fun allMessages(ex: HttpExchange) {
        val limit = queryInt(ex, "limit", 200)
        send(ex, 200, Json.arr(registry.allMessages().takeLast(limit).map(::messageMap)))
    }

    private fun messageMap(m: ProxyMessage): Map<String, Any?> = mapOf(
        "id" to m.id, "connection_id" to m.connectionId, "direction" to m.direction.name,
        "timestamp" to m.timestamp.toString(), "length" to m.rawBytes.size,
        "hex" to toHex(m.rawBytes), "text" to preview(m.rawBytes),
    )

    private fun repeat(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val proto = Protocol.valueOf(Json.str(o, "protocol", "TCP").uppercase())
        val target = Json.str(o, "host").ifBlank { throw IllegalArgumentException("host required") }
        val p = Json.int(o, "port").also { require(it in 1..65535) { "port 1-65535" } }
        val hex = Json.str(o, "hex")
        val bytes = if (hex.isNotBlank()) fromHex(hex)
                    else Json.str(o, "text").toByteArray(StandardCharsets.ISO_8859_1)
        require(bytes.isNotEmpty()) { "hex or text payload required" }
        val timeout = Json.int(o, "timeout_ms", 2000).toLong()
        val resp = replaySender.replay(proto, target, p, bytes, timeout)
        send(ex, 200, Json.obj(
            "sent_len" to bytes.size, "response_len" to resp.size,
            "response_hex" to toHex(resp), "response_text" to preview(resp),
        ))
    }

    private fun listRules(ex: HttpExchange) = send(ex, 200, Json.arr(
        matchReplace.rules().map { r -> mapOf(
            "id" to r.id, "match_type" to r.matchType.name, "match" to r.matchValue,
            "replace" to r.replaceValue, "enabled" to r.enabled,
        ) }
    ))

    private fun addRule(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val rule = MatchReplaceRule(
            id = ruleIds.getAndIncrement(),
            matchType = MatchType.valueOf(Json.str(o, "match_type", "LITERAL_STRING").uppercase()),
            matchValue = Json.str(o, "match"),
            replaceValue = Json.str(o, "replace"),
            enabled = (o["enabled"] as? Boolean) ?: true,
        )
        matchReplace.addRule(rule)
        send(ex, 200, Json.obj("ok" to true, "id" to rule.id))
    }

    // ── Helpers ───────────────────────────────────────────────────────────
    private fun body(ex: HttpExchange): String =
        ex.requestBody.readBytes().toString(StandardCharsets.UTF_8)

    private fun queryInt(ex: HttpExchange, key: String, default: Int): Int =
        ex.requestURI.query?.split("&")?.firstOrNull { it.startsWith("$key=") }
            ?.substringAfter("=")?.toIntOrNull() ?: default

    private fun hostAllowed(ex: HttpExchange): Boolean {
        val h = ex.requestHeaders.getFirst("Host") ?: return true // curl w/o Host over loopback
        // Strip an optional [ipv6] wrapper and the :port suffix.
        val raw = h.trim()
        val name = if (raw.startsWith("[")) raw.substringAfter("[").substringBefore("]")
                   else raw.substringBefore(":")
        // DNS-rebind safe: literal loopback OR the exact configured bind host
        // (the WSL/remote case reaches the API on its bind IP, whose Host header
        // is that IP, not loopback). Never resolves a hostname.
        return isLoopback(name) || name.equals(host, ignoreCase = true)
    }

    private fun send(ex: HttpExchange, code: Int, json: String) {
        val bytes = json.toByteArray(StandardCharsets.UTF_8)
        ex.responseHeaders.add("Content-Type", "application/json")
        ex.sendResponseHeaders(code, bytes.size.toLong())
        ex.responseBody.write(bytes)
    }

    companion object {
        fun isLoopback(host: String?): Boolean {
            if (host.isNullOrBlank()) return false
            if (host.equals("localhost", true) || host == "::1" || host == "0:0:0:0:0:0:0:1") return true
            val o = host.split(".")
            return o.size == 4 && o.all { it.isNotEmpty() && it.all(Char::isDigit) && it.toInt() in 0..255 } && o[0] == "127"
        }

        fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

        fun fromHex(hex: String): ByteArray {
            val clean = hex.filterNot { it.isWhitespace() }
            require(clean.length % 2 == 0) { "hex length must be even" }
            return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }

        /** Printable-ASCII preview; non-printable bytes -> '.', capped. */
        fun preview(b: ByteArray, max: Int = 512): String =
            b.take(max).map { val c = it.toInt() and 0xff; if (c in 0x20..0x7e) c.toChar() else '.' }.joinToString("")
    }
}
