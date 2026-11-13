package expedition.session

import expedition.dns.DnsRedirector
import expedition.engine.ListenerConfig
import expedition.engine.Socks5ListenerConfig
import expedition.engine.TlsMode
import expedition.engine.UpstreamProxy
import expedition.framing.DEFAULT_MAX_FRAME_BYTES
import expedition.framing.FramingSpec
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.registry.Protocol
import expedition.server.Json
import java.nio.ByteOrder

/** Thin key/value seam over Burp's `PersistedObject` so the logic below has no Burp dependency. */
interface ConfigStore {
    fun get(key: String): String?
    fun set(key: String, value: String?)
}

/** In-memory [ConfigStore] (tests, and the fallback when no persistence is available). */
class MapConfigStore(val map: MutableMap<String, String> = HashMap()) : ConfigStore {
    override fun get(key: String): String? = map[key]
    override fun set(key: String, value: String?) { if (value == null) map.remove(key) else map[key] = value }
}

/** A fixed bind->upstream listener plus whether it was running when saved. */
data class SavedListener(val config: ListenerConfig, val running: Boolean)

/** A SOCKS5 dynamic listener plus whether it was running when saved. */
data class SavedSocks5Listener(val config: Socks5ListenerConfig, val running: Boolean)

/** DNS redirector settings (rules, catch-all IP, bind port). Never auto-started on restore. */
data class DnsSettings(val rules: List<DnsRedirector.Rule>, val defaultIp: String?, val port: Int)

data class SavedConfig(
    val listeners: List<SavedListener> = emptyList(),
    val socks5Listeners: List<SavedSocks5Listener> = emptyList(),
    val rules: List<MatchReplaceRule> = emptyList(),
    val script: String? = null,
    val dns: DnsSettings? = null,
    /** Declarative HTTP rules (expedition.rules), in evaluation order. */
    val httpRules: List<expedition.rules.HttpRule> = emptyList(),
)

data class DecodeResult(val config: SavedConfig, val warnings: List<String>)

/**
 * Pure (de)serialisation of [SavedConfig] as JSON. Secrets are never written: the upstream
 * client-certificate keystore password and the SOCKS5 password. A listener that cannot work
 * without such a secret (client cert / SOCKS5 auth) is left out of the file entirely rather
 * than being restored in a silently weaker form. [decode] is tolerant: a corrupt document or a
 * bad entry yields warnings and whatever could be recovered, never an exception.
 */
object ConfigCodec {
    const val VERSION = 1

    /** Names of listeners [encode] omits because they carry a secret that is not persisted. */
    fun unpersistable(config: SavedConfig): List<String> =
        config.listeners.filter { it.config.upstreamClientAuth != null }.map { it.config.name } +
            config.socks5Listeners.filter { it.config.username != null || it.config.upstreamClientAuth != null }
                .map { it.config.name }

    fun encode(config: SavedConfig): String {
        val tcp = config.listeners.filter { it.config.upstreamClientAuth == null }.map { l ->
            val c = l.config
            mapOf<String, Any?>(
                "name" to c.name, "protocol" to c.protocol.name,
                "bindHost" to c.bindHost, "bindPort" to c.bindPort,
                "upstreamHost" to c.upstreamHost, "upstreamPort" to c.upstreamPort,
                "tlsMode" to c.tlsMode.name,
                "upstreamProxy" to c.upstreamProxy?.let { "${it.host}:${it.port}" },
                "framing" to framingMap(c.framing),
                "tlsPassthrough" to c.tlsPassthrough,
                "running" to l.running,
            )
        }
        val socks = config.socks5Listeners
            .filter { it.config.username == null && it.config.upstreamClientAuth == null }.map { l ->
                val c = l.config
                mapOf<String, Any?>(
                    "name" to c.name, "bindHost" to c.bindHost, "bindPort" to c.bindPort,
                    "tlsMode" to c.tlsMode.name,
                    "upstreamProxy" to c.upstreamProxy?.let { "${it.host}:${it.port}" },
                    "tlsPassthrough" to c.tlsPassthrough,
                    "running" to l.running,
                )
            }
        val rules = config.rules.map {
            mapOf<String, Any?>(
                "id" to it.id, "matchType" to it.matchType.name, "matchValue" to it.matchValue,
                "replaceValue" to it.replaceValue, "enabled" to it.enabled, "decoded" to it.decoded,
            )
        }
        val dns = config.dns?.let { d ->
            mapOf<String, Any?>(
                "rules" to d.rules.map { mapOf("host" to it.hostPattern, "ip" to it.ip) },
                "defaultIp" to d.defaultIp, "port" to d.port,
            )
        }
        return Json.obj(
            "version" to VERSION, "listeners" to tcp, "socks5Listeners" to socks,
            "rules" to rules, "script" to config.script, "dns" to dns,
            "httpRules" to config.httpRules.map { expedition.rules.RuleCodec.toMap(it) },
        )
    }

    private fun framingMap(f: FramingSpec): Map<String, Any?> = when (f) {
        is FramingSpec.Passthrough -> mapOf("type" to "passthrough")
        is FramingSpec.LengthPrefix -> mapOf(
            "type" to "length", "offset" to f.lengthFieldOffset, "size" to f.lengthFieldSize,
            "order" to if (f.byteOrder == ByteOrder.LITTLE_ENDIAN) "little" else "big",
            "adjustment" to f.lengthAdjustment, "max" to f.maxFrameBytes,
        )
        is FramingSpec.Delimiter -> mapOf(
            "type" to "delimiter", "hex" to f.delimiter.joinToString("") { "%02x".format(it) },
            "max" to f.maxFrameBytes,
        )
    }

    fun decode(text: String?): DecodeResult {
        val warnings = mutableListOf<String>()
        if (text.isNullOrBlank()) return DecodeResult(SavedConfig(), warnings)
        val root = try {
            Json.parse(text) as? Map<*, *> ?: run {
                warnings += "saved configuration is not a JSON object; ignored"
                return DecodeResult(SavedConfig(), warnings)
            }
        } catch (e: Exception) {
            warnings += "saved configuration is corrupt (${e.message}); ignored"
            return DecodeResult(SavedConfig(), warnings)
        }
        fun items(key: String): List<Map<String, Any?>> =
            (root[key] as? List<*>)?.mapNotNull { e -> (e as? Map<*, *>)?.let { Json.asObject(it) } } ?: emptyList()

        val listeners = items("listeners").mapNotNull { guard("listener", it, warnings) { decodeListener(it) } }
        val socks = items("socks5Listeners").mapNotNull { guard("socks5 listener", it, warnings) { decodeSocks(it) } }
        val rules = items("rules").mapNotNull { guard("match/replace rule", it, warnings) { decodeRule(it) } }
        val script = (root["script"] as? String)?.takeIf { it.isNotBlank() }
        val dns = (root["dns"] as? Map<*, *>)?.let { d ->
            guard("dns settings", Json.asObject(d), warnings) { decodeDns(it) }
        }
        val httpRules = items("httpRules").mapNotNull { guard("http rule", it, warnings) { r -> expedition.rules.RuleCodec.fromMap(r) } }
        return DecodeResult(SavedConfig(listeners, socks, rules, script, dns, httpRules), warnings)
    }

    private fun <T> guard(what: String, o: Map<String, Any?>, warnings: MutableList<String>, f: (Map<String, Any?>) -> T): T? =
        try { f(o) } catch (e: Exception) {
            warnings += "skipped invalid $what '${o["name"] ?: ""}': ${e.message}"; null
        }

    private fun intOf(o: Map<String, Any?>, key: String): Int =
        (o[key] as? Number)?.toInt() ?: throw IllegalArgumentException("missing/invalid '$key'")

    private fun need(o: Map<String, Any?>, key: String): String =
        (o[key] as? String)?.takeIf { it.isNotBlank() } ?: throw IllegalArgumentException("missing '$key'")

    private fun port(o: Map<String, Any?>, key: String): Int =
        intOf(o, key).also { require(it in 0..65535) { "'$key' out of range" } }

    private fun upstreamProxy(o: Map<String, Any?>): UpstreamProxy? {
        val s = (o["upstreamProxy"] as? String)?.takeIf { it.isNotBlank() } ?: return null
        val i = s.lastIndexOf(':')
        require(i > 0) { "invalid upstreamProxy" }
        val p = s.substring(i + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("invalid upstreamProxy port")
        return UpstreamProxy(s.substring(0, i), p)
    }

    private fun decodeListener(o: Map<String, Any?>) = SavedListener(
        ListenerConfig(
            name = need(o, "name"), protocol = Protocol.valueOf(need(o, "protocol")),
            bindHost = need(o, "bindHost"), bindPort = port(o, "bindPort"),
            upstreamHost = need(o, "upstreamHost"), upstreamPort = port(o, "upstreamPort"),
            tlsMode = (o["tlsMode"] as? String)?.let { TlsMode.valueOf(it) } ?: TlsMode.NONE,
            upstreamProxy = upstreamProxy(o),
            framing = decodeFraming(o["framing"]),
            tlsPassthrough = (o["tlsPassthrough"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList(),
        ),
        running = o["running"] == true,
    )

    private fun decodeSocks(o: Map<String, Any?>) = SavedSocks5Listener(
        Socks5ListenerConfig(
            name = need(o, "name"), bindHost = need(o, "bindHost"), bindPort = port(o, "bindPort"),
            tlsMode = (o["tlsMode"] as? String)?.let { TlsMode.valueOf(it) } ?: TlsMode.NONE,
            upstreamProxy = upstreamProxy(o),
            tlsPassthrough = (o["tlsPassthrough"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList(),
        ),
        running = o["running"] == true,
    )

    private fun decodeFraming(v: Any?): FramingSpec {
        val f = (v as? Map<*, *>)?.let { Json.asObject(it) } ?: return FramingSpec.Passthrough
        return when (val type = f["type"] as? String ?: "passthrough") {
            "passthrough" -> FramingSpec.Passthrough
            "length" -> FramingSpec.LengthPrefix(
                lengthFieldOffset = intOf(f, "offset"), lengthFieldSize = intOf(f, "size"),
                byteOrder = if (f["order"] == "little") ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN,
                lengthAdjustment = (f["adjustment"] as? Number)?.toInt() ?: 0,
                maxFrameBytes = (f["max"] as? Number)?.toInt() ?: DEFAULT_MAX_FRAME_BYTES,
            )
            "delimiter" -> {
                val hex = need(f, "hex")
                require(hex.length % 2 == 0 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) { "bad delimiter hex" }
                FramingSpec.Delimiter(
                    ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() },
                    (f["max"] as? Number)?.toInt() ?: DEFAULT_MAX_FRAME_BYTES,
                )
            }
            else -> throw IllegalArgumentException("unknown framing '$type'")
        }
    }

    private fun decodeRule(o: Map<String, Any?>) = MatchReplaceRule(
        id = (o["id"] as? Number)?.toLong() ?: throw IllegalArgumentException("missing 'id'"),
        matchType = MatchType.valueOf(need(o, "matchType")),
        matchValue = (o["matchValue"] as? String) ?: throw IllegalArgumentException("missing 'matchValue'"),
        replaceValue = (o["replaceValue"] as? String) ?: "",
        enabled = o["enabled"] != false,
        decoded = o["decoded"] == true,
    )

    private fun decodeDns(o: Map<String, Any?>): DnsSettings {
        val rules = (o["rules"] as? List<*>)?.mapNotNull { r ->
            val m = Json.asObject(r)
            val h = (m["host"] as? String)?.takeIf { it.isNotBlank() }
            val ip = (m["ip"] as? String)?.takeIf { it.isNotBlank() }
            if (h != null && ip != null) DnsRedirector.Rule(h, ip) else null
        } ?: emptyList()
        return DnsSettings(rules, (o["defaultIp"] as? String)?.takeIf { it.isNotBlank() }, (o["port"] as? Number)?.toInt() ?: 53)
    }
}

/**
 * Saves/restores the operator's configuration (listeners, match & replace rules, active script,
 * DNS rules) through a [ConfigStore]. Listener configs are tracked here as they are created;
 * the running flag is computed at save time from [runningNames], rules and script are read live
 * from their owners. [save] never throws (persistence failure must not break traffic handling).
 */
class ConfigPersistence(
    private val store: ConfigStore,
    private val rules: () -> List<MatchReplaceRule>,
    private val script: () -> String?,
    private val runningNames: () -> Set<String>,
    private val log: (String) -> Unit = {},
    private val httpRules: () -> List<expedition.rules.HttpRule> = { emptyList() },
) {
    private val tcp = LinkedHashMap<String, ListenerConfig>()
    private val socks = LinkedHashMap<String, Socks5ListenerConfig>()
    private var dns: DnsSettings? = null

    /** Records [config] (replacing any same-named entry) for the next [save]. */
    @Synchronized fun trackListener(config: ListenerConfig) { tcp[config.name] = config; socks.remove(config.name) }
    @Synchronized fun trackSocks5(config: Socks5ListenerConfig) { socks[config.name] = config; tcp.remove(config.name) }
    /** Forgets a listener entirely (it will not come back on restore). */
    @Synchronized fun forgetListener(name: String) { tcp.remove(name); socks.remove(name) }
    @Synchronized fun setDns(settings: DnsSettings?) { dns = settings }

    /** Loads the stored config (never throws) and seeds the tracker with the restored listeners/DNS. */
    @Synchronized
    fun load(): DecodeResult {
        val result = try {
            ConfigCodec.decode(store.get(KEY))
        } catch (e: Exception) {
            DecodeResult(SavedConfig(), listOf("could not read saved configuration: ${e.message}"))
        }
        result.config.listeners.forEach { tcp[it.config.name] = it.config }
        result.config.socks5Listeners.forEach { socks[it.config.name] = it.config }
        dns = result.config.dns
        result.warnings.forEach { log("config restore: $it") }
        return result
    }

    /**
     * [load] for restoring into a live extension from a project that may not be trusted:
     * every listener comes back STOPPED (the operator starts it explicitly) whatever its saved
     * running flag, so opening a project never binds a socket. The script stays text only —
     * callers hand it to [expedition.script.ScriptHooks.restorePending], never setScript.
     */
    @Synchronized
    fun loadForRestore(): DecodeResult {
        val r = load()
        val c = r.config
        return r.copy(config = c.copy(
            listeners = c.listeners.map { it.copy(running = false) },
            socks5Listeners = c.socks5Listeners.map { it.copy(running = false) },
            // Rules from an untrusted project (redirect, mock bodyFile, webhook, delay, M&R...) never
            // apply until the operator reviews and enables them; content is kept intact.
            rules = c.rules.map { it.copy(enabled = false) },
            httpRules = c.httpRules.map { it.copy(enabled = false) },
        ))
    }

    fun save() {
        try {
            val snapshot = snapshot()
            val skipped = ConfigCodec.unpersistable(snapshot)
            if (skipped.isNotEmpty()) log("config save: not persisting listeners that need a secret: $skipped")
            store.set(KEY, ConfigCodec.encode(snapshot))
        } catch (e: Exception) {
            log("config save failed: ${e.message}")
        }
    }

    @Synchronized
    fun snapshot(): SavedConfig {
        val running = runningNames()
        return SavedConfig(
            listeners = tcp.values.map { SavedListener(it, it.name in running) },
            socks5Listeners = socks.values.map { SavedSocks5Listener(it, it.name in running) },
            rules = rules(), script = script(), dns = dns, httpRules = httpRules(),
        )
    }

    companion object { const val KEY = "expedition.config.v1" }
}
