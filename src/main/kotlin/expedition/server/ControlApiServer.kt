package expedition.server

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import expedition.engine.ListenerConfig
import expedition.engine.TlsMode
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.session.FlowTagStore
import expedition.session.SessionSnapshot
import expedition.session.SessionStore
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import expedition.registry.ProxyMessage
import expedition.fuzz.ByteMutator
import expedition.fuzz.Fuzzer
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
 * Security model:
 *  - every request must carry `Authorization: Bearer <token>` (compared in constant time); when
 *    no token is supplied a random one is generated ([token]) — the API is never open;
 *  - a non-loopback bind is refused unless the operator set the token explicitly
 *    ([tokenExplicit]);
 *  - the Host header must be literal loopback or the bind host (DNS-rebinding safe, never
 *    resolves a hostname) and any browser request (Origin / Sec-Fetch-* headers) is refused;
 *  - file paths received over the API are confined to [dataDir] ([PathSandbox]).
 */
class ControlApiServer(
    private val host: String,
    private val port: Int,
    private val registry: ConnectionRegistry,
    private val matchReplace: MatchReplaceEngine,
    private val intercept: InterceptController,
    private val startListener: (ListenerConfig) -> Unit,
    private val stopListener: (String) -> Unit,
    private val runningListeners: () -> Set<String>,
    private val startSocks5Listener: (expedition.engine.Socks5ListenerConfig) -> Unit = {},
    private val replaySender: ReplaySender = ReplaySender(),
    private val flowTagStore: FlowTagStore = FlowTagStore(),
    private val scriptHooks: expedition.script.ScriptHooks? = null,
    private val dnsController: expedition.dns.DnsController? = null,
    private val version: String = expedition.BuildInfo.VERSION,
    /**
     * Bearer token every request must carry. Null generates a random per-instance token
     * (readable via [token]); the API is never served without authentication.
     */
    authToken: String? = null,
    /** Declarative HTTP rules engine exposed under /rules (null = routes answer 404). */
    private val rulesEngine: expedition.rules.RulesEngine? = null,
    /** True when the operator chose the token (env var) — required for a non-loopback bind. */
    private val tokenExplicit: Boolean = authToken != null,
    /** The only directory API-supplied file paths may resolve into (default `~/.expedition`). */
    dataDir: java.io.File = PathSandbox.defaultBase(),
) {
    /** The bearer token clients must present. */
    val token: String = authToken?.takeIf { it.isNotBlank() } ?: ApiToken.generate()
    private val sandbox = PathSandbox(dataDir)
    private var server: HttpServer? = null
    private val setupService = expedition.setup.SetupService(caDir = dataDir, untrusted = true)
    private var executor: java.util.concurrent.ExecutorService? = null
    private var slowExecutor: java.util.concurrent.ThreadPoolExecutor? = null

    /** True when the API is bound beyond loopback (operator's risk — remote/WSL). */
    fun isExposedBeyondLoopback(): Boolean = !isLoopback(host)

    fun start() {
        // Default is loopback (secure). A non-loopback bind (NAT-mode WSL reaching Burp via the
        // host IP) is allowed only with an operator-chosen token; the caller logs the warning.
        require(isLoopback(host) || tokenExplicit) {
            "refusing to bind the control API to non-loopback host '$host' without an explicitly configured token (EXPEDITION_API_TOKEN)"
        }
        val s = HttpServer.create(InetSocketAddress(host, port), 0)
        val threadId = AtomicLong(1)
        val pool = Executors.newFixedThreadPool(4) { r ->
            Thread(r, "expedition-ctrl-api-${threadId.getAndIncrement()}").apply { isDaemon = true }
        }
        // Slow, network-bound work (repeat/fuzz/setup apply) runs on its own bounded pool so it
        // cannot starve status/evidence reads; a full queue answers 503.
        val slow = java.util.concurrent.ThreadPoolExecutor(
            SLOW_THREADS, SLOW_THREADS, 30, java.util.concurrent.TimeUnit.SECONDS,
            java.util.concurrent.ArrayBlockingQueue(SLOW_QUEUE),
        ) { r -> Thread(r, "expedition-ctrl-api-slow-${threadId.getAndIncrement()}").apply { isDaemon = true } }
        s.executor = pool
        executor = pool
        slowExecutor = slow
        s.createContext("/") { ex -> dispatch(ex) }
        s.start()
        server = s
    }

    fun stop() {
        server?.stop(0)
        server = null
        // HttpServer.stop() does not touch an application-supplied executor — shut it
        // down ourselves or its worker threads leak and pin the extension classloader.
        executor?.shutdownNow()
        executor = null
        slowExecutor?.shutdownNow()
        slowExecutor = null
    }

    private fun isSlow(ex: HttpExchange): Boolean {
        val p = ex.requestURI.path.trimEnd('/')
        return ex.requestMethod == "POST" && (p == "/repeat" || p == "/fuzz" || (p.startsWith("/setup/") && (p.endsWith("/apply") || p.endsWith("/undo"))))
    }

    private fun dispatch(ex: HttpExchange) {
        val slow = slowExecutor
        if (slow == null || !isSlow(ex)) { safeHandle(ex); return }
        try {
            slow.execute { safeHandle(ex) }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            try { send(ex, 503, Json.obj("error" to "too many slow requests in flight; retry later")) } finally { ex.close() }
        }
    }

    private fun safeHandle(ex: HttpExchange) {
        try {
            if (!hostAllowed(ex)) { send(ex, 403, Json.obj("error" to "non-loopback Host rejected")); return }
            if (!originAllowed(ex)) { send(ex, 403, Json.obj("error" to "browser requests are not allowed")); return }
            if (!authorized(ex)) { send(ex, 401, Json.obj("error" to "missing or invalid auth token")); return }
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
            method == "GET" && path.matches(Regex("/connections/\\d+/tags")) ->
                getConnectionTags(ex, path.split("/")[2].toLong())
            method == "GET" && path == "/messages" -> allMessages(ex)
            method == "POST" && path == "/repeat" -> repeat(ex)
            method == "POST" && path == "/fuzz" -> fuzz(ex)
            method == "GET" && path == "/matchreplace" -> listRules(ex)
            method == "POST" && path == "/matchreplace" -> addRule(ex)
            method == "DELETE" && path.startsWith("/matchreplace/") -> {
                matchReplace.removeRule(path.removePrefix("/matchreplace/").toLong())
                send(ex, 200, Json.obj("ok" to true))
            }
            method == "GET" && path == "/intercept" -> interceptState(ex)
            method == "POST" && path == "/intercept/enable" -> interceptEnable(ex)
            method == "POST" && path.matches(Regex("/intercept/\\d+/forward")) ->
                interceptForward(ex, path.split("/")[2].toLong())
            method == "POST" && path.matches(Regex("/intercept/\\d+/drop")) -> {
                intercept.drop(path.split("/")[2].toLong()); send(ex, 200, Json.obj("ok" to true))
            }
            method == "POST" && path.matches(Regex("/connections/\\d+/tag")) ->
                tagConnection(ex, path.split("/")[2].toLong())
            method == "GET" && path == "/messages/search" -> searchMessages(ex)
            method == "GET" && path == "/session/export" -> exportSession(ex)
            method == "POST" && path == "/session/save" -> sessionSave(ex)
            method == "POST" && path == "/session/load" -> sessionLoad(ex)
            method == "GET" && path == "/script" -> scriptStatus(ex)
            method == "POST" && path == "/script" -> setScript(ex)
            method == "DELETE" && path == "/script" -> clearScript(ex)
            method == "GET" && path == "/export/har" -> send(ex, 200, expedition.export.ExportApi.exportHar(registry, queryParam(ex, "connection")))
            method == "POST" && path == "/import/har" -> send(ex, 200, expedition.export.ExportApi.importHar(registry, body(ex)))
            method == "GET" && path == "/export/snippet" -> send(ex, 200, expedition.export.ExportApi.snippet(registry, queryParam(ex, "connection"), queryParam(ex, "message"), queryParam(ex, "target")))
            method == "GET" && path == "/dns" -> dnsStatus(ex)
            method == "POST" && path == "/dns/start" -> dnsStart(ex)
            method == "POST" && path == "/dns/stop" -> dnsStop(ex)
            method == "POST" && path == "/analysis/openapi" -> analysisOpenApi(ex)
            method == "GET" && path == "/analysis/report" -> analysisReport(ex)
            path == "/rules" || path.startsWith("/rules/") -> (rulesEngine?.let { expedition.rules.RulesApi(it, registry).handle(method, path, if (method == "POST" || method == "PUT") body(ex) else "") }
                ?: (404 to Json.obj("error" to "rules engine not available"))).let { (code, json) -> send(ex, code, json) }
            path == "/setup" || path.startsWith("/setup/") -> setupService.handle(method, path, ex.requestURI.rawQuery, if (method == "POST") body(ex) else "")
                .let { (code, json) -> send(ex, code, json) }
            else -> send(ex, 404, Json.obj("error" to "no route: $method $path"))
        }
    }

    // ── Handlers ────────────────────────────────────────────────────────────
    private fun analysisOpenApi(ex: HttpExchange) {
        // Body: the raw OpenAPI document (JSON/YAML) or {"spec": "<text>"}; empty body clears the spec.
        val raw = body(ex).trim()
        if (raw.isEmpty()) { expedition.analysis.AnalysisService.clearOpenApi(); send(ex, 200, Json.obj("ok" to true, "loaded" to false)); return }
        val text = if (raw.startsWith("{") && Json.asObject(Json.parse(raw)).let { it.containsKey("spec") && !it.containsKey("openapi") })
            Json.str(Json.asObject(Json.parse(raw)), "spec") else raw
        val spec = expedition.analysis.AnalysisService.loadOpenApi(text)
        send(ex, 200, Json.obj("ok" to true, "loaded" to true, "title" to spec.title, "openapi" to spec.version, "operations" to spec.operationCount))
    }

    private fun analysisReport(ex: HttpExchange) {
        val conn = queryParam(ex, "connection")?.let { it.toLongOrNull() ?: throw IllegalArgumentException("connection must be a number") }
        val findings = expedition.analysis.AnalysisService.report(registry, conn)
        send(ex, 200, Json.obj(
            "openapi" to (expedition.analysis.AnalysisService.spec != null),
            "count" to findings.size,
            "errors" to findings.count { it.severity == expedition.analysis.Severity.ERROR },
            "warnings" to findings.count { it.severity == expedition.analysis.Severity.WARNING },
            "findings" to findings.map { it.toMap() },
        ))
    }

    private fun status(ex: HttpExchange) = send(ex, 200, Json.obj(
        "version" to version,
        "running_listeners" to runningListeners().toList(),
        "connections" to registry.allConnections().size,
        "messages" to registry.allMessages().size,
    ))

    private fun addListener(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val name = Json.str(o, "name").ifBlank { throw IllegalArgumentException("name required") }
        val bindHost = Json.str(o, "bind_host", "127.0.0.1")
        requireLoopbackOrOptIn(o, bindHost, "bind_host")
        val bindPort = Json.int(o, "bind_port").also { require(it in 1..65535) { "bind_port 1-65535" } }

        val tlsMode = when (Json.str(o, "tls", "none").lowercase()) {
            "mitm" -> TlsMode.MITM
            "starttls" -> TlsMode.STARTTLS
            else -> TlsMode.NONE
        }
        val proxyStr = Json.str(o, "upstream_proxy")
        val proxy = if (proxyStr.isBlank()) null else {
            val idx = proxyStr.lastIndexOf(':')
            require(idx > 0) { "upstream_proxy must be host:port" }
            expedition.engine.UpstreamProxy(proxyStr.substring(0, idx),
                proxyStr.substring(idx + 1).toInt().also { require(it in 1..65535) { "upstream_proxy port 1-65535" } })
        }
        val certPath = Json.str(o, "client_cert")
        val clientAuth = if (certPath.isBlank()) null else {
            val certFile = sandbox.resolve(certPath)
            require(certFile.isFile) { "client_cert not found: $certPath" }
            expedition.engine.UpstreamClientAuth(certFile, Json.str(o, "client_cert_password").toCharArray())
        }
        val passthrough = parsePassthrough(o)
        // UDP relay has no upstream-proxy or client-cert path; refuse rather than silently ignore.
        if (Json.str(o, "protocol", "TCP").equals("udp", true) && (proxy != null || clientAuth != null)) {
            throw IllegalArgumentException("upstream_proxy/client_cert are not supported for UDP")
        }

        // SOCKS5 dynamic listener: no fixed upstream (destination negotiated per connection).
        if (Json.str(o, "protocol", "TCP").equals("socks5", true)) {
            val user = Json.str(o, "username")
            startSocks5Listener(expedition.engine.Socks5ListenerConfig(
                name, bindHost, bindPort,
                tlsMode = tlsMode,
                upstreamProxy = proxy,
                upstreamClientAuth = clientAuth,
                tlsPassthrough = passthrough,
                username = user.ifEmpty { null },
                password = if (user.isEmpty()) null else Json.str(o, "password"),
            ))
            send(ex, 200, Json.obj("ok" to true, "name" to name)); return
        }

        val cfg = ListenerConfig(
            name = name,
            protocol = Protocol.valueOf(Json.str(o, "protocol", "TCP").uppercase()),
            bindHost = bindHost,
            bindPort = bindPort,
            upstreamHost = Json.str(o, "upstream_host").ifBlank { throw IllegalArgumentException("upstream_host required") },
            upstreamPort = Json.int(o, "upstream_port").also { require(it in 1..65535) { "upstream_port 1-65535" } },
            tlsMode = tlsMode,
            upstreamClientAuth = clientAuth,
            upstreamProxy = proxy,
            framing = parseFraming(o),
            tlsPassthrough = passthrough,
        )
        startListener(cfg)
        send(ex, 200, Json.obj("ok" to true, "name" to cfg.name))
    }

    /**
     * Optional `"tls_passthrough"`: SNI patterns (`host` or `*.suffix`) relayed raw instead of
     * MITM'd. Accepts a JSON array of strings or a comma-separated string; default empty.
     */
    private fun parsePassthrough(o: Map<String, Any?>): List<String> {
        val raw = when (val v = o["tls_passthrough"]) {
            null -> emptyList()
            is String -> v.split(',')
            is List<*> -> v.map { it as? String ?: throw IllegalArgumentException("tls_passthrough entries must be strings") }
            else -> throw IllegalArgumentException("tls_passthrough must be an array of strings or a comma-separated string")
        }
        val patterns = raw.map { it.trim() }.filter { it.isNotEmpty() }
        patterns.forEach {
            require(expedition.engine.tls.TlsPassthroughMatcher.isValidPattern(it)) { "invalid tls_passthrough pattern '$it' (use host or *.suffix)" }
        }
        return patterns
    }

    /**
     * Optional TCP framing: `"framing":"passthrough"` (default) | `"length"` (with `length_offset`,
     * `length_size` 1/2/3/4/8, `length_endian` big|little, `length_adjust`) | `"delimiter"` (with
     * `delimiter` text, e.g. "\r\n", or `delimiter_hex`). `max_frame_bytes` caps buffering.
     */
    private fun parseFraming(o: Map<String, Any?>): expedition.framing.FramingSpec {
        val max = Json.int(o, "max_frame_bytes", expedition.framing.DEFAULT_MAX_FRAME_BYTES)
        require(max > 0) { "max_frame_bytes must be > 0" }
        return when (val kind = Json.str(o, "framing", "passthrough").lowercase()) {
            "", "passthrough", "none" -> expedition.framing.FramingSpec.Passthrough
            "length", "length_prefix", "length-prefix" -> expedition.framing.FramingSpec.LengthPrefix(
                lengthFieldOffset = Json.int(o, "length_offset", 0),
                lengthFieldSize = Json.int(o, "length_size", 4),
                byteOrder = when (Json.str(o, "length_endian", "big").lowercase()) {
                    "big", "be" -> java.nio.ByteOrder.BIG_ENDIAN
                    "little", "le" -> java.nio.ByteOrder.LITTLE_ENDIAN
                    else -> throw IllegalArgumentException("length_endian must be big or little")
                },
                lengthAdjustment = Json.int(o, "length_adjust", 0),
                maxFrameBytes = max,
            )
            "delimiter", "delimited", "line" -> {
                val hex = Json.str(o, "delimiter_hex")
                val delim = when {
                    hex.isNotBlank() -> fromHex(hex)
                    o.containsKey("delimiter") -> Json.str(o, "delimiter").toByteArray(StandardCharsets.ISO_8859_1)
                    else -> "\r\n".toByteArray(StandardCharsets.ISO_8859_1)
                }
                expedition.framing.FramingSpec.Delimiter(delim, max)
            }
            else -> throw IllegalArgumentException("unknown framing '$kind' (passthrough|length|delimiter)")
        }
    }

    private fun connections(ex: HttpExchange) = send(ex, 200, Json.arr(
        registry.allConnections().map { c ->
            val tags = flowTagStore.tags(c.connectionId)
            mapOf(
                "id" to c.connectionId, "listener" to c.listenerName, "protocol" to c.protocol.name,
                "client" to c.clientAddress, "upstream" to c.upstreamAddress,
                "opened_at" to c.openedAt.toString(), "closed_at" to (c.closedAt?.toString()),
                "tags" to tags.toList(),
            )
        }
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
        val timeout = Json.int(o, "timeout_ms", 2000).toLong().coerceIn(1, MAX_TIMEOUT_MS)
        val resp = replaySender.replay(proto, target, p, bytes, timeout)
        send(ex, 200, Json.obj(
            "sent_len" to bytes.size, "response_len" to resp.size,
            "response_hex" to toHex(resp), "response_text" to preview(resp),
        ))
    }

    private fun fuzz(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val proto = Protocol.valueOf(Json.str(o, "protocol", "TCP").uppercase())
        val host = Json.str(o, "host").ifBlank { throw IllegalArgumentException("host required") }
        val port = Json.int(o, "port").also { require(it in 1..65535) { "port 1-65535" } }
        val hex = Json.str(o, "hex")
        val seed = if (hex.isNotBlank()) fromHex(hex)
                   else Json.str(o, "text").toByteArray(StandardCharsets.ISO_8859_1)
        require(seed.isNotEmpty()) { "hex or text seed required" }
        val iterations = Json.int(o, "iterations", 50).coerceIn(1, 500)
        val timeout = Json.int(o, "timeout_ms", 2000).toLong().coerceIn(1, MAX_FUZZ_TIMEOUT_MS)
        val randomSeed = (o["random_seed"] as? Number)?.toLong() ?: System.currentTimeMillis()
        val mutator = ByteMutator(kotlin.random.Random(randomSeed))
        val fuzzer = Fuzzer(replaySender)
        val cases = fuzzer.fuzz(proto, host, port, seed, iterations, mutator, timeout)
        val results = cases.mapIndexed { i, c -> mapOf(
            "index" to i,
            "input_len" to c.input.size,
            "response_len" to c.response.size,
            "input_hex" to toHex(c.input).take(200),
            "response_hex" to toHex(c.response).take(200),
            "response_text" to preview(c.response),
        ) }
        val anomalies = cases.mapIndexedNotNull { i, c ->
            if (c.response.isEmpty()) i else null
        }
        send(ex, 200, Json.obj(
            "iterations" to cases.size,
            "seed_len" to seed.size,
            "anomalies" to anomalies.size,
            "anomaly_indices" to anomalies.take(20),
            "results" to results,
        ))
    }

    private fun listRules(ex: HttpExchange) = send(ex, 200, Json.arr(
        matchReplace.rules().map { r -> mapOf(
            "id" to r.id, "match_type" to r.matchType.name, "match" to r.matchValue,
            "replace" to r.replaceValue, "enabled" to r.enabled, "decoded" to r.decoded,
        ) }
    ))

    private fun addRule(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val rule = try {
            val type = try {
                MatchType.valueOf(Json.str(o, "match_type", "LITERAL_STRING").uppercase())
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("match_type must be one of ${MatchType.values().joinToString()}")
            }
            fun boolField(key: String, default: Boolean): Boolean = when (val v = o[key]) {
                null -> default
                is Boolean -> v
                else -> throw IllegalArgumentException("$key must be a boolean")
            }
            val decoded = boolField("decoded", false)
            if (decoded && type == MatchType.LITERAL_BYTES) {
                throw IllegalArgumentException("decoded rules require match_type LITERAL_STRING or REGEX")
            }
            MatchReplaceRule(
                id = matchReplace.nextRuleId(),
                matchType = type,
                matchValue = Json.str(o, "match"),
                replaceValue = Json.str(o, "replace"),
                enabled = boolField("enabled", true),
                decoded = decoded,
            )
        } catch (e: IllegalArgumentException) {
            send(ex, 400, Json.obj("error" to (e.message ?: "invalid rule"))); return
        }
        matchReplace.addRule(rule)
        send(ex, 200, Json.obj("ok" to true, "id" to rule.id))
    }

    private fun interceptState(ex: HttpExchange) = send(ex, 200, Json.obj(
        "enabled" to intercept.isEnabled(),
        "held" to intercept.heldMessages().map { h -> mapOf(
            "id" to h.id, "connection_id" to h.connectionId, "direction" to h.direction,
            "length" to h.bytes.size, "hex" to toHex(h.bytes), "text" to preview(h.bytes),
        ) },
    ))

    private fun interceptEnable(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        intercept.setEnabled((o["enabled"] as? Boolean) ?: true)
        send(ex, 200, Json.obj("ok" to true, "enabled" to intercept.isEnabled()))
    }

    private fun interceptForward(ex: HttpExchange, id: Long) {
        val o = Json.asObject(Json.parse(body(ex)))
        val hex = Json.str(o, "hex")
        // Forward the edited bytes if supplied, else the original held bytes.
        val edited = when {
            hex.isNotBlank() -> fromHex(hex)
            Json.str(o, "text").isNotEmpty() -> Json.str(o, "text").toByteArray(StandardCharsets.ISO_8859_1)
            else -> intercept.heldBytes(id) ?: throw IllegalArgumentException("no held message $id")
        }
        intercept.forward(id, edited)
        send(ex, 200, Json.obj("ok" to true, "forwarded_len" to edited.size))
    }

    // ── Tag / Search / Session ─────────────────────────────────────────
    private fun tagConnection(ex: HttpExchange, connId: Long) {
        val o = Json.asObject(Json.parse(body(ex)))
        val color = Json.str(o, "color")
        val comment = Json.str(o, "comment")
        val tag = listOfNotNull(color.ifBlank { null }, comment.ifBlank { null }).joinToString("|")
        if (tag.isBlank()) {
            send(ex, 400, Json.obj("error" to "color or comment required")); return
        }
        flowTagStore.tag(connId, tag)
        send(ex, 200, Json.obj("ok" to true, "tags" to flowTagStore.tags(connId).toList()))
    }

    private fun getConnectionTags(ex: HttpExchange, connId: Long) {
        send(ex, 200, Json.obj("connection_id" to connId, "tags" to flowTagStore.tags(connId).toList()))
    }

    private fun exportSession(ex: HttpExchange) {
        val snapshot = SessionSnapshot(
            registry.allConnections(), registry.allMessages(), flowTagStore.all()
        )
        val json = SessionStore.export(snapshot)
        send(ex, 200, json)
    }

    private fun searchMessages(ex: HttpExchange) {
        val q = queryParam(ex, "q") ?: ""
        if (q.isBlank()) { send(ex, 400, Json.obj("error" to "q= query param required")); return }
        val limit = queryInt(ex, "limit", 50)
        val matches = registry.allMessages()
            .filter { preview(it.rawBytes).contains(q, ignoreCase = true) }
            .takeLast(limit)
        send(ex, 200, Json.arr(matches.map(::messageMap)))
    }

    private fun sessionSave(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val file = sandbox.resolve(Json.str(o, "path").ifBlank { "expedition-session.json" })
        require(!java.nio.file.Files.isSymbolicLink(file.toPath())) { "refusing to write through a symlink" }
        val snapshot = SessionSnapshot(
            registry.allConnections(), registry.allMessages(), flowTagStore.all()
        )
        val json = SessionStore.export(snapshot)
        file.parentFile?.mkdirs()
        file.writeText(json, StandardCharsets.UTF_8)
        send(ex, 200, Json.obj(
            "ok" to true, "path" to file.path,
            "connections" to snapshot.connections.size,
            "messages" to snapshot.messages.size,
            "tags" to snapshot.tags.size,
        ))
    }

    private fun sessionLoad(ex: HttpExchange) {
        val o = Json.asObject(Json.parse(body(ex)))
        val path = Json.str(o, "path").ifBlank {
            send(ex, 400, Json.obj("error" to "path required")); return
        }
        val file = sandbox.resolve(path)
        if (!file.isFile) { send(ex, 404, Json.obj("error" to "file not found: $path")); return }
        val snapshot = SessionStore.import(file.readText(StandardCharsets.UTF_8))
        val restored = SessionStore.restore(snapshot, registry, flowTagStore)
        send(ex, 200, Json.obj(
            "ok" to true,
            "connections" to snapshot.connections.size,
            "messages" to snapshot.messages.size,
            "tags" to snapshot.tags.size,
            "connections_added" to restored.connectionsAdded,
            "messages_added" to restored.messagesAdded,
            "skipped_duplicates" to restored.skippedDuplicates,
        ))
    }

    // ── Scripting (JSR-223 operator hook) ───────────────────────────────────
    private fun scriptStatus(ex: HttpExchange) {
        val h = scriptHooks
        if (h == null) { send(ex, 200, Json.obj("available" to false)); return }
        send(ex, 200, Json.obj(
            "available" to h.engineAvailable,
            "installed" to (h.source != null),
            "source" to h.source,
            "last_error" to h.lastError,
        ))
    }

    private fun setScript(ex: HttpExchange) {
        val h = scriptHooks ?: run { send(ex, 404, Json.obj("error" to "scripting not available")); return }
        val o = Json.asObject(Json.parse(body(ex)))
        val source = Json.str(o, "source").ifBlank { send(ex, 400, Json.obj("error" to "source required")); return }
        h.setScript(source) // throws IllegalArgumentException on compile error -> 400 via safeHandle
        send(ex, 200, Json.obj("ok" to true, "installed" to true))
    }

    private fun clearScript(ex: HttpExchange) {
        val h = scriptHooks ?: run { send(ex, 404, Json.obj("error" to "scripting not available")); return }
        h.setScript(null)
        send(ex, 200, Json.obj("ok" to true, "installed" to false))
    }

    // ── DNS redirector ──────────────────────────────────────────────────────
    private fun dnsStatus(ex: HttpExchange) {
        val d = dnsController ?: run { send(ex, 404, Json.obj("error" to "DNS not available")); return }
        send(ex, 200, Json.obj(d.status()))
    }

    private fun dnsStart(ex: HttpExchange) {
        val d = dnsController ?: run { send(ex, 404, Json.obj("error" to "DNS not available")); return }
        val o = Json.asObject(Json.parse(body(ex)))
        val host = Json.str(o, "host", "127.0.0.1")
        requireLoopbackOrOptIn(o, host, "host")
        val port = Json.int(o, "port", 53)
        val defaultIp = Json.str(o, "default_ip").ifBlank { null }
        val rules = (o["rules"] as? List<*>).orEmpty().mapNotNull { r ->
            val m = r as? Map<*, *> ?: return@mapNotNull null
            val hp = (m["host"] as? String)?.ifBlank { null } ?: return@mapNotNull null
            val ip = (m["ip"] as? String)?.ifBlank { null } ?: return@mapNotNull null
            expedition.dns.DnsRedirector.Rule(hp, ip)
        }
        if (rules.isEmpty() && defaultIp == null) {
            send(ex, 400, Json.obj("error" to "at least one rule or a default_ip is required")); return
        }
        val bound = try { d.start(host, port, rules, defaultIp) }
        catch (e: java.net.BindException) {
            send(ex, 409, Json.obj("error" to "cannot bind DNS on $host:$port (port 53 needs privileges): ${e.message}")); return
        }
        send(ex, 200, Json.obj("ok" to true, "host" to host, "port" to bound))
    }

    private fun dnsStop(ex: HttpExchange) {
        val d = dnsController ?: run { send(ex, 404, Json.obj("error" to "DNS not available")); return }
        d.stop()
        send(ex, 200, Json.obj("ok" to true, "running" to false))
    }

    // ── Helpers ───────────────────────────────────────────────────────────
    /**
     * A non-loopback bind address exposes a listener/resolver to the network, so it must be
     * requested explicitly with `"allow_non_loopback": true` in the body. Otherwise → 400.
     */
    private fun requireLoopbackOrOptIn(o: Map<String, Any?>, host: String, field: String) {
        if (isLoopback(host)) return
        require(o["allow_non_loopback"] == true) {
            "$field '$host' is not loopback; set \"allow_non_loopback\": true to bind beyond 127.0.0.1/::1/localhost"
        }
    }

    private fun body(ex: HttpExchange): String {
        // Buffer at most MAX_BODY_BYTES, but keep draining (discarding) the rest of an
        // over-cap body: com.sun HttpServer resets the connection if we respond without
        // consuming the request, which would deny the client the clean 400. Memory stays
        // bounded to one buffer + the cap; IllegalArgumentException maps to 400 upstream.
        val stream = ex.requestBody
        val kept = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0L
        var over = false
        while (true) {
            val n = stream.read(buf)
            if (n < 0) break
            total += n
            if (total > MAX_BODY_BYTES) over = true else kept.write(buf, 0, n)
        }
        require(!over) { "request body too large (> $MAX_BODY_BYTES bytes)" }
        return kept.toString(StandardCharsets.UTF_8)
    }

    private fun queryInt(ex: HttpExchange, key: String, default: Int): Int =
        queryParam(ex, key)?.toIntOrNull() ?: default

    /**
     * Returns the decoded value of [key] from the request query string, or null when absent.
     * Uses the RAW query (URI.getQuery() is already decoded, which would double-decode `%25`)
     * and decodes it as application/x-www-form-urlencoded: `+` → space, `%XX` → UTF-8 byte.
     * A malformed escape throws IllegalArgumentException, mapped to 400 by safeHandle.
     */
    private fun queryParam(ex: HttpExchange, key: String): String? = queryValue(ex.requestURI.rawQuery, key)

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

    /** Requires an exact `Bearer <token>` match, compared in constant time (digests of equal
     *  length) so a wrong token can't be recovered by timing. */
    private fun authorized(ex: HttpExchange): Boolean {
        val header = ex.requestHeaders.getFirst("Authorization") ?: return false
        if (!header.startsWith("Bearer ")) return false
        val presented = header.removePrefix("Bearer ").trim()
        val sha = { s: String -> java.security.MessageDigest.getInstance("SHA-256").digest(s.toByteArray(StandardCharsets.UTF_8)) }
        return java.security.MessageDigest.isEqual(sha(presented), sha(token))
    }

    /**
     * CSRF / DNS-rebinding defense: the API is for CLI/MCP clients, never for web pages. A
     * browser attaches `Origin` (cross-origin and every POST) and `Sec-Fetch-*` headers; a
     * legitimate client sends none, so any of them is refused — even a loopback Origin, which
     * could be another local web app.
     */
    private fun originAllowed(ex: HttpExchange): Boolean {
        val h = ex.requestHeaders
        if (h.getFirst("Origin") != null) return false
        return h.keys.none { it.startsWith("Sec-Fetch-", ignoreCase = true) }
    }

    private fun send(ex: HttpExchange, code: Int, json: String) {
        val bytes = json.toByteArray(StandardCharsets.UTF_8)
        ex.responseHeaders.add("Content-Type", "application/json")
        ex.sendResponseHeaders(code, bytes.size.toLong())
        ex.responseBody.write(bytes)
    }

    companion object {
        /** Cap on a control request body (4 MiB) — generous for repeat/fuzz seeds, bounded
         *  against a memory-exhaustion POST to the loopback API. */
        const val MAX_BODY_BYTES = 4 * 1024 * 1024
        /** Upper bound for a /repeat `timeout_ms`. */
        const val MAX_TIMEOUT_MS = 30_000L
        /** Upper bound for a per-iteration /fuzz `timeout_ms` (up to 500 iterations). */
        const val MAX_FUZZ_TIMEOUT_MS = 5_000L
        private const val SLOW_THREADS = 4
        private const val SLOW_QUEUE = 16

        fun isLoopback(host: String?): Boolean {
            if (host.isNullOrBlank()) return false
            if (host.equals("localhost", true) || host == "::1" || host == "0:0:0:0:0:0:0:1") return true
            val o = host.split(".")
            return o.size == 4 && o.all { it.isNotEmpty() && it.all(Char::isDigit) && it.toInt() in 0..255 } && o[0] == "127"
        }

        /**
         * Decoded value of [key] in a RAW query string (`a=1&b=2`), or null when absent.
         * Form-style decoding: `+` → space, `%XX` → UTF-8 byte; a malformed escape throws
         * IllegalArgumentException (mapped to 400). Pure, so it is unit tested directly.
         */
        fun queryValue(rawQuery: String?, key: String): String? {
            if (rawQuery.isNullOrEmpty()) return null
            val prefix = "$key="
            val pair = rawQuery.split("&").firstOrNull { it.startsWith(prefix) } ?: return null
            return java.net.URLDecoder.decode(pair.substring(prefix.length), StandardCharsets.UTF_8)
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
