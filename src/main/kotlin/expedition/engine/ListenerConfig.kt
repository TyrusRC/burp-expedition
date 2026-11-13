package expedition.engine

import expedition.registry.Protocol
import java.io.File

enum class TlsMode { NONE, MITM, STARTTLS }

/** Client certificate the proxy presents to a mutual-TLS upstream (loaded from PKCS#12). */
class UpstreamClientAuth(val keystorePath: File, val keystorePassword: CharArray)

/** An outbound SOCKS5 proxy the upstream connection is chained through (e.g. to reach Burp). */
data class UpstreamProxy(val host: String, val port: Int)

data class ListenerConfig(
    val name: String,
    val protocol: Protocol,
    val bindHost: String,
    val bindPort: Int,
    val upstreamHost: String,
    val upstreamPort: Int,
    val tlsMode: TlsMode = TlsMode.NONE,
    val upstreamClientAuth: UpstreamClientAuth? = null,
    val upstreamProxy: UpstreamProxy? = null,
    /** How each TCP direction is split into messages before the gate (UDP ignores this). */
    val framing: expedition.framing.FramingSpec = expedition.framing.FramingSpec.Passthrough,
    /**
     * MITM only: SNI patterns (`host` or `*.suffix`) whose TLS is relayed raw instead of being
     * intercepted. Empty (default) = MITM everything.
     */
    val tlsPassthrough: List<String> = emptyList()
)
