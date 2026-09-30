package expedition.engine

/**
 * A SOCKS5 dynamic listener: one bound port that relays to whatever destination each
 * client negotiates via the SOCKS5 handshake (unlike [ListenerConfig], which is a fixed
 * bind→upstream pair). This is how a proxy-aware but multi-destination client (or a
 * `proxychains`-wrapped one) routes arbitrary TCP through the proxy.
 */
data class Socks5ListenerConfig(
    val name: String,
    val bindHost: String,
    val bindPort: Int
)
