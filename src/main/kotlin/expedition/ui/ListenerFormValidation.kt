package expedition.ui

import expedition.engine.ListenerConfig
import expedition.engine.TlsMode
import expedition.registry.Protocol

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
        certificateProviderConfigured: Boolean = false
    ): Result<ListenerConfig> {
        if (name.isBlank()) return Result.failure(IllegalArgumentException("Name must not be blank"))
        if (name in existingNames) return Result.failure(IllegalArgumentException("A listener named '$name' already exists"))
        val bindPortInt = bindPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: return Result.failure(IllegalArgumentException("Bind port must be 1-65535"))
        val upstreamPortInt = upstreamPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: return Result.failure(IllegalArgumentException("Upstream port must be 1-65535"))
        if (upstreamHost.isBlank()) return Result.failure(IllegalArgumentException("Upstream host must not be blank"))
        if (bindHost.isBlank()) return Result.failure(IllegalArgumentException("Bind host must not be blank"))
        if (tlsMode == TlsMode.MITM && !certificateProviderConfigured) {
            return Result.failure(IllegalArgumentException("Configure a CA keystore before adding a TLS MITM listener"))
        }
        return Result.success(ListenerConfig(name, protocol, bindHost, bindPortInt, upstreamHost, upstreamPortInt, tlsMode))
    }
}
