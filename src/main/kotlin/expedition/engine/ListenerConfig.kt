package expedition.engine

import expedition.registry.Protocol
import java.io.File

enum class TlsMode { NONE, MITM }

/** Client certificate the proxy presents to a mutual-TLS upstream (loaded from PKCS#12). */
class UpstreamClientAuth(val keystorePath: File, val keystorePassword: CharArray)

data class ListenerConfig(
    val name: String,
    val protocol: Protocol,
    val bindHost: String,
    val bindPort: Int,
    val upstreamHost: String,
    val upstreamPort: Int,
    val tlsMode: TlsMode = TlsMode.NONE,
    val upstreamClientAuth: UpstreamClientAuth? = null
)
