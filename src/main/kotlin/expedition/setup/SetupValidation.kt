package expedition.setup

/**
 * Strict allow-list validation of setup parameters. Several values end up in argv lists
 * (adb, frida, browsers) — and `adb shell` re-joins its arguments into a device-side shell
 * command line — or in generated files (Firefox user.js) and pasteable shell snippets. Every
 * value is therefore restricted to a character set with no shell, quote or option syntax.
 * Throws [IllegalArgumentException] (mapped to HTTP 400 by the control API).
 */
object SetupValidation {
    /** DNS hostname (RFC 1123 labels) or IPv4 literal. */
    private val HOSTNAME = Regex("^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
    /** IPv6 literal (hex groups and colons only, optionally bracketed). */
    private val IPV6 = Regex("^\\[?[0-9A-Fa-f:]{2,39}]?$")
    private val SOCKS_USER = Regex("^[A-Za-z0-9._@-]{1,64}$")
    private val SERIAL = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    /** Android package / iOS bundle id: dot-separated identifiers. */
    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(?:[.-][A-Za-z0-9_]+)*$")
    private val STOREPASS = Regex("^[A-Za-z0-9._@%+=,:!#^*~-]{1,128}$")
    private val URL = Regex("^(?:https?://[A-Za-z0-9._~:/?#\\[\\]@!$&()*+,;=%-]+|about:blank)$")
    /** Bare executable name (resolved from PATH) — no path, no option prefix. */
    private val EXE_NAME = Regex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")

    fun isHost(s: String): Boolean = HOSTNAME.matches(s) || (s.contains(':') && IPV6.matches(s))

    fun requireHost(name: String, v: String) =
        require(isHost(v)) { "$name must be a hostname or IP address" }

    fun requireHostPort(name: String, v: String) {
        val i = v.lastIndexOf(':')
        require(i > 0) { "$name must be host:port" }
        requireHost(name, v.substring(0, i))
        require(v.substring(i + 1).toIntOrNull() in 1..65535) { "$name port must be 1-65535" }
    }

    fun isExecutableName(s: String) = EXE_NAME.matches(s)

    /** Validates the shared fields and every known target parameter of [ctx]. */
    fun check(ctx: SetupContext, target: SetupTarget? = null) {
        requireHost("host", ctx.host)
        require(ctx.port in 1..65535) { "port must be 1-65535" }
        // Any parameter that declares options must be one of them.
        target?.params?.forEach { spec ->
            val v = ctx.params[spec.name]
            if (spec.options.isNotEmpty() && !v.isNullOrBlank())
                require(v in spec.options) { "${spec.name} must be one of ${spec.options}" }
        }
        ctx.params.forEach { (k, v) ->
            if (v.isBlank()) return@forEach
            when (k) {
                "device_host", "gateway" -> requireHost(k, v)
                "serial" -> require(SERIAL.matches(v)) { "serial contains invalid characters" }
                "package" -> require(PACKAGE.matches(v) && v.length <= 255) { "package must be a package/bundle id (letters, digits, '.', '_', '-')" }
                "remote_host" -> requireHostPort(k, v)
                "username" -> require(SOCKS_USER.matches(v)) { "username may only contain letters, digits, '.', '_', '@', '-' (max 64)" }
                "password" -> require(STOREPASS.matches(v)) { "password contains invalid characters" }
                "storepass" -> require(STOREPASS.matches(v)) { "storepass contains invalid characters" }
                "url" -> require(URL.matches(v)) { "url must be http(s)://… or about:blank" }
                "binary" -> require(!v.startsWith("-") && v.none { it.isISOControl() }) { "binary is not a valid executable" }
                "truststore" -> require(!v.startsWith("-") && v.none { it.isISOControl() }) { "truststore is not a valid path" }
            }
        }
    }
}
