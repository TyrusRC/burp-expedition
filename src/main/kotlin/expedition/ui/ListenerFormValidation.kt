package expedition.ui

import expedition.engine.ListenerConfig
import expedition.engine.TlsMode
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
        clientCertPassword: CharArray? = null
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
        return Result.success(
            ListenerConfig(name, protocol, bindHost, bindPortInt, upstreamHost, upstreamPortInt, tlsMode, clientAuth, proxy)
        )
    }
}
