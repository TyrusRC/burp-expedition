package expedition.engine.tls

import expedition.engine.ListenerConfig
import expedition.engine.StartTlsDetector
import expedition.engine.TcpConnection
import expedition.tls.BurpCertificateProvider
import io.netty.channel.Channel
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Drives a plaintext→TLS (STARTTLS) upgrade on a live relay. Detection runs on the bytes
 * actually FORWARDED through the message gate (i.e. after any interceptor hold/edit), not on
 * raw pipeline bytes — so it stays correct when Intercept is enabled: the plaintext go-ahead
 * is delivered to the client first, and only then are the TLS handlers inserted.
 *
 * NOTE: one upgrade per connection. The SslHandler is inserted via the channel's event loop,
 * which runs after the just-issued go-ahead write is already queued on that loop.
 */
class StartTlsCoordinator(
    private val detector: StartTlsDetector,
    private val provider: BurpCertificateProvider,
    private val config: ListenerConfig,
    /** Called with the connection id once the client-side TLS (MITM) handshake succeeded. */
    private val onMitmHandshake: (Long) -> Unit = {}
) {
    private val upgraded = AtomicBoolean(false)

    /** Feed client→upstream bytes as forwarded to the upstream (post-intercept). */
    fun onClientForwarded(bytes: ByteArray) {
        if (!upgraded.get()) detector.onClientData(bytes)
    }

    /** True if this forwarded upstream→client chunk is the server's go-ahead (upgrade needed). */
    fun isGoAhead(bytes: ByteArray): Boolean = !upgraded.get() && detector.onUpstreamData(bytes)

    /**
     * Insert the TLS handlers. Call from the CLIENT channel's event loop, right after the plaintext
     * go-ahead has been written, so the SNI router is in place before the client's ClientHello can
     * arrive. The router mints the client-facing leaf from the ClientHello's SNI (fallback: the
     * listener's upstream host); only then is upstream TLS started (with that SNI), or — if the
     * SNI matches `tls_passthrough` — the connection switches to a raw relay.
     */
    fun upgrade(clientChannel: Channel, connection: TcpConnection) {
        if (!upgraded.compareAndSet(false, true)) return
        val router = SniTlsRouter(provider, config.upstreamHost, TlsPassthroughMatcher(config.tlsPassthrough),
            onMitmHandshake = { onMitmHandshake(connection.connectionId) }) { _, decision ->
            when (decision) {
                is TlsDecision.Passthrough -> { connection.enterPassthrough(decision.sni); null }
                is TlsDecision.Mitm -> connection.startUpstreamTls(decision.sni ?: config.upstreamHost, decision.alpn)
            }
        }
        clientChannel.pipeline().addFirst(SniTlsRouter.NAME, router)
    }
}
