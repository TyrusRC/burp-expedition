package expedition.setup

import expedition.server.Json
import java.io.File
import java.net.URLDecoder

/** Registry + HTTP-facing dispatcher for the setup targets. */
class SetupService(
    private val caDir: File = File(System.getenv("EXPEDITION_CA_DIR")?.takeIf { it.isNotBlank() }
        ?: (System.getProperty("user.home") + File.separator + ".expedition")),
    private val runner: CommandRunner = ProcessRunner(),
    val targets: List<SetupTarget> = ALL_TARGETS,
    /**
     * True when parameters come from the control API rather than the local UI: file paths
     * (`ca`, `truststore`) are then confined to [caDir], and `binary` must be a known browser
     * name or an executable the operator declared in `EXPEDITION_BROWSER_BINARIES`.
     */
    private val untrusted: Boolean = false,
    private val declaredBinaries: List<String> = (System.getenv("EXPEDITION_BROWSER_BINARIES") ?: "")
        .split(File.pathSeparatorChar).map { it.trim() }.filter { it.isNotEmpty() },
) {
    val state = SetupState()
    val caFile: File get() = File(caDir, "expedition-ca.crt")
    private val sandbox = expedition.server.PathSandbox(caDir)

    fun find(id: String): SetupTarget? = targets.firstOrNull { it.id == id }

    /** [base] holds host/port/proxy_type/ca plus target params, all as strings. Throws IllegalArgumentException on invalid values. */
    fun context(base: Map<String, String>, target: SetupTarget? = null): SetupContext {
        val reserved = setOf("host", "port", "proxy_type", "ca")
        val params = base.filterKeys { it !in reserved }.toMutableMap()
        val ca = base["ca"]?.takeIf { it.isNotBlank() }?.let { if (untrusted) sandbox.resolve(it) else File(it) } ?: caFile
        if (untrusted) {
            params["truststore"]?.takeIf { it.isNotBlank() }?.let { params["truststore"] = sandbox.resolve(it).path }
            params["binary"]?.takeIf { it.isNotBlank() }?.let { requireAllowedBinary(it) }
        }
        val ctx = SetupContext(
            host = base["host"]?.takeIf { it.isNotBlank() } ?: "127.0.0.1",
            port = base["port"]?.toIntOrNull()?.takeIf { it in 1..65535 } ?: 8080,
            caCert = ca,
            proxyType = if (base["proxy_type"] == "http") "http" else "socks5",
            params = params,
            runner = runner, state = state,
        )
        SetupValidation.check(ctx, target)
        return ctx
    }

    private fun requireAllowedBinary(bin: String) {
        if (bin in KNOWN_BROWSERS) return
        val f = File(bin)
        val declared = declaredBinaries.any { d -> runCatching { File(d).canonicalPath == f.canonicalPath }.getOrDefault(false) }
        require(declared && f.isFile && f.canExecute()) {
            "binary must be one of $KNOWN_BROWSERS or an executable listed in EXPEDITION_BROWSER_BINARIES"
        }
    }

    fun describe(): List<Map<String, Any?>> = targets.map { t ->
        mapOf("id" to t.id, "title" to t.title, "executable" to t.executable,
            "params" to t.params.map { mapOf("name" to it.name, "label" to it.label, "default" to it.default, "options" to it.options) })
    }

    /** Handles /setup... Returns (status, json). */
    fun handle(method: String, path: String, rawQuery: String?, body: String): Pair<Int, String> {
        val parts = path.trim('/').split('/')
        if (parts.firstOrNull() != "setup") return 404 to Json.obj("error" to "no route")
        if (parts.size == 2 && parts[1] == "targets" && method == "GET") return 200 to Json.arr(describe())
        val target = parts.getOrNull(1)?.let { find(it) } ?: return 404 to Json.obj("error" to "unknown setup target")
        val q = parseQuery(rawQuery)
        return try { dispatch(method, path, parts, target, q, body) }
        catch (e: IllegalArgumentException) { 400 to Json.obj("error" to (e.message ?: "invalid setup parameter")) }
    }

    private fun dispatch(method: String, path: String, parts: List<String>, target: SetupTarget, q: Map<String, String>, body: String): Pair<Int, String> {
        return when {
            parts.size == 2 && method == "GET" -> {
                val ctx = context(q, target)
                200 to Json.obj("target" to target.id, "ca" to ctx.caPath, "guide" to target.guide(ctx))
            }
            parts.size == 3 && method == "POST" && (parts[2] == "apply" || parts[2] == "undo") -> {
                val o = if (body.isBlank()) emptyMap() else Json.asObject(Json.parse(body))
                val flat = q.toMutableMap()
                o.forEach { (k, v) -> if (k != "params" && v != null) flat[k] = if (v is Double && v == v.toLong().toDouble()) v.toLong().toString() else v.toString() }
                Json.asObject(o["params"]).forEach { (k, v) -> if (v != null) flat[k] = v.toString() }
                val ctx = context(flat, target)
                val r = if (parts[2] == "apply") target.apply(ctx) else target.undo(ctx)
                (if (r.ok) 200 else 422) to Json.obj("ok" to r.ok, "log" to r.log)
            }
            else -> 404 to Json.obj("error" to "no route: $method $path")
        }
    }

    companion object {
        /** Browser executables accepted by name (resolved from PATH) over the control API. */
        val KNOWN_BROWSERS: Set<String> = setOf(
            "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
            "microsoft-edge", "microsoft-edge-stable", "brave-browser", "firefox", "firefox-esr",
        )

        val ALL_TARGETS: List<SetupTarget> = listOf(
            AdbTarget, FridaTarget, TerminalTarget, DockerTarget, JvmTarget, BrowserTarget, OsTarget, BurpChainTarget,
        )

        fun parseQuery(raw: String?): Map<String, String> = raw.orEmpty().split('&').filter { it.contains('=') }.associate {
            URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8")
        }
    }
}
