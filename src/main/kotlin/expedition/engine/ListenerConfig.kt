package expedition.engine

import expedition.registry.Protocol

enum class TlsMode { NONE, MITM }

data class ListenerConfig(
    val name: String,
    val protocol: Protocol,
    val bindHost: String,
    val bindPort: Int,
    val upstreamHost: String,
    val upstreamPort: Int,
    val tlsMode: TlsMode = TlsMode.NONE
)
