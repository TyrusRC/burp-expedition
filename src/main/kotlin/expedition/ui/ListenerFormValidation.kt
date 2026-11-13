package expedition.ui

import expedition.engine.ListenerConfig
import expedition.engine.Socks5ListenerConfig
import expedition.engine.TlsMode
import expedition.framing.DEFAULT_MAX_FRAME_BYTES
import expedition.framing.FramingSpec
import expedition.engine.UpstreamClientAuth
import expedition.engine.UpstreamProxy
import expedition.registry.Protocol
import java.io.File

object ListenerFormValidation {
    fun validate(
        name: String,
        protocol: Protocol,
        bindHost: String,
        bindPort: String,
        upstreamHost: String,
        upstreamPort: String,
        tlsMode: TlsMode,
        existingNames: Set<String>,
        certificateProviderConfigured: Boolean = false,
        upstreamProxy: String = "",
        clientCertPath: String = "",
        clientCertPassword: CharArray? = null,
        framing: FramingForm = FramingForm(),
        tlsPassthrough: String = ""
    ): Result<ListenerConfig> {
        if (name.isBlank()) return Result.failure(IllegalArgumentException("Name must not be blank"))
        if (name in existingNames) return Result.failure(IllegalArgumentException("A listener named '$name' already exists"))
        val bindPortInt = bindPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: return Result.failure(IllegalArgumentException("Bind port must be 1-65535"))
        val upstreamPortInt = upstreamPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: return Result.failure(IllegalArgumentException("Upstream port must be 1-65535"))
        if (upstreamHost.isBlank()) return Result.failure(IllegalArgumentException("Upstream host must not be blank"))
        if (bindHost.isBlank()) return Result.failure(IllegalArgumentException("Bind host must not be blank"))
        if ((tlsMode == TlsMode.MITM || tlsMode == TlsMode.STARTTLS) && !certificateProviderConfigured) {
            return Result.failure(IllegalArgumentException("Configure a CA keystore before adding a TLS MITM/STARTTLS listener"))
        }
        val proxy = if (upstreamProxy.isBlank()) null else {
            val idx = upstreamProxy.lastIndexOf(':')
            val proxyPort = if (idx > 0) upstreamProxy.substring(idx + 1).toIntOrNull() else null
            if (idx <= 0 || proxyPort == null || proxyPort !in 1..65535) {
                return Result.failure(IllegalArgumentException("Upstream proxy must be host:port"))
            }
            UpstreamProxy(upstreamProxy.substring(0, idx), proxyPort)
        }
        val clientAuth = if (clientCertPath.isBlank()) null
            else UpstreamClientAuth(File(clientCertPath), clientCertPassword ?: CharArray(0))
        if (protocol == Protocol.UDP && (proxy != null || clientAuth != null)) {
            return Result.failure(IllegalArgumentException("Upstream proxy and client certificate are not supported for UDP"))
        }
        val spec = framing.toSpec().getOrElse { return Result.failure(it) }
        val passthrough = parsePassthrough(tlsPassthrough).getOrElse { return Result.failure(it) }
        if (passthrough.isNotEmpty() && tlsMode != TlsMode.MITM) {
            return Result.failure(IllegalArgumentException("TLS passthrough patterns only apply to TLS mode MITM"))
        }
        return Result.success(
            ListenerConfig(name, protocol, bindHost, bindPortInt, upstreamHost, upstreamPortInt, tlsMode, clientAuth, proxy, spec, passthrough)
        )
    }

    /** Validates a SOCKS5 listener form (TLS mode, optional username/password). */
    fun validateSocks5(
        name: String, bindHost: String, bindPort: String, tlsMode: TlsMode, existingNames: Set<String>,
        certificateProviderConfigured: Boolean = false, tlsPassthrough: String = "",
        username: String = "", password: String = ""
    ): Result<Socks5ListenerConfig> = runCatching {
        require(name.isNotBlank() && name !in existingNames) { "SOCKS5 listener needs a unique name" }
        val port = bindPort.toIntOrNull()?.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("Bind port must be 1-65535")
        require(tlsMode != TlsMode.STARTTLS) { "STARTTLS is not supported on a SOCKS5 listener" }
        require(tlsMode != TlsMode.MITM || certificateProviderConfigured) { "Configure a CA keystore before adding a TLS MITM listener" }
        val pt = parsePassthrough(tlsPassthrough).getOrThrow()
        require(pt.isEmpty() || tlsMode == TlsMode.MITM) { "TLS passthrough patterns only apply to TLS mode MITM" }
        require(username.isNotEmpty() || password.isEmpty()) { "A password needs a username" }
        Socks5ListenerConfig(name, bindHost.trim().ifBlank { "127.0.0.1" }, port, tlsMode,
            tlsPassthrough = pt, username = username.ifEmpty { null }, password = if (username.isEmpty()) null else password)
    }

    /** Comma/whitespace separated SNI patterns: `host` or `*.suffix`. */
    fun parsePassthrough(text: String): Result<List<String>> {
        val items = text.split(',', ' ', '\n', ';').map { it.trim() }.filter { it.isNotEmpty() }
        val bad = items.firstOrNull { !Regex("^(\\*\\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$").matches(it) }
        return if (bad != null) Result.failure(IllegalArgumentException("Invalid TLS passthrough pattern '$bad' (use host or *.suffix)"))
        else Result.success(items)
    }

    /** True for 127.0.0.0/8, ::1 and "localhost"; anything else exposes the proxy to the network. */
    fun isLoopbackBind(host: String): Boolean {
        val h = host.trim().lowercase().ifEmpty { return true }
        if (h == "localhost" || h == "::1" || h == "[::1]") return true
        return Regex("^127(\\.\\d{1,3}){3}$").matches(h)
    }

    fun nonLoopbackWarning(host: String): String? =
        if (isLoopbackBind(host)) null
        else "Binding to '${host.trim()}' exposes this listener (an open relay to the upstream) to other machines. Continue?"
}

/** Raw framing fields from the form. [type] is Passthrough, LengthPrefix or Delimiter. */
data class FramingForm(
    val type: String = "Passthrough",
    val lengthOffset: String = "0",
    val lengthSize: String = "4",
    val bigEndian: Boolean = true,
    val lengthAdjustment: String = "0",
    val delimiter: String = "",
    val maxFrameBytes: String = ""
) {
    fun toSpec(): Result<FramingSpec> = runCatching {
        val max = maxFrameBytes.trim().ifEmpty { null }?.let { it.toIntOrNull() ?: throw IllegalArgumentException("Max frame bytes must be a number") }
        when (type) {
            "Passthrough" -> FramingSpec.Passthrough
            "LengthPrefix" -> FramingSpec.LengthPrefix(
                lengthOffset.trim().toIntOrNull() ?: throw IllegalArgumentException("Length offset must be a number"),
                lengthSize.trim().toIntOrNull() ?: throw IllegalArgumentException("Length size must be a number"),
                if (bigEndian) java.nio.ByteOrder.BIG_ENDIAN else java.nio.ByteOrder.LITTLE_ENDIAN,
                lengthAdjustment.trim().toIntOrNull() ?: throw IllegalArgumentException("Length adjustment must be a number"),
                max ?: DEFAULT_MAX_FRAME_BYTES
            )
            "Delimiter" -> {
                val bytes = unescape(delimiter)
                FramingSpec.Delimiter(bytes, max ?: DEFAULT_MAX_FRAME_BYTES)
            }
            else -> throw IllegalArgumentException("Unknown framing '$type'")
        }
    }

    private fun unescape(s: String): ByteArray =
        s.replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t").toByteArray(Charsets.ISO_8859_1)
}
