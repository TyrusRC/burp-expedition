package expedition.engine

/**
 * A SOCKS5 dynamic listener: one bound port that relays to whatever destination each
 * client negotiates via the SOCKS5 handshake (unlike [ListenerConfig], which is a fixed
 * bind→upstream pair). This is how a proxy-aware but multi-destination client (or a
 * `proxychains`-wrapped one) routes arbitrary TCP through the proxy.
 *
 * [tlsMode], [upstreamProxy], [upstreamClientAuth] and [tlsPassthrough] apply to every
 * negotiated destination exactly as on a fixed [ListenerConfig]. When [username] is set the
 * listener requires RFC 1929 username/password auth; by default no auth is required.
 */
data class Socks5ListenerConfig(
    val name: String,
    val bindHost: String,
    val bindPort: Int,
    val tlsMode: TlsMode = TlsMode.NONE,
    val upstreamProxy: UpstreamProxy? = null,
    val upstreamClientAuth: UpstreamClientAuth? = null,
    val tlsPassthrough: List<String> = emptyList(),
    val username: String? = null,
    val password: String? = null
) {
    init {
        require(tlsMode != TlsMode.STARTTLS) { "STARTTLS is not supported on a SOCKS5 listener" }
        require(username == null || (username.length in 1..255 && (password ?: "").length <= 255)) {
            "SOCKS5 username/password must be 1-255 / 0-255 bytes"
        }
    }

    val requiresAuth: Boolean get() = username != null

    override fun toString(): String =
        "Socks5ListenerConfig(name=$name, bind=$bindHost:$bindPort, tls=$tlsMode, auth=${if (requiresAuth) "user/pass" else "none"})"
}
