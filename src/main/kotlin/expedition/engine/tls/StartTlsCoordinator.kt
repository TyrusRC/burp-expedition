package expedition.engine.tls

import expedition.engine.ListenerConfig
import expedition.engine.StartTlsDetector
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
    private val config: ListenerConfig
) {
    private val upgraded = AtomicBoolean(false)

    /** Feed client→upstream bytes as forwarded to the upstream (post-intercept). */
    fun onClientForwarded(bytes: ByteArray) {
        if (!upgraded.get()) detector.onClientData(bytes)
    }

    /** True if this forwarded upstream→client chunk is the server's go-ahead (upgrade needed). */
    fun isGoAhead(bytes: ByteArray): Boolean = !upgraded.get() && detector.onUpstreamData(bytes)

    /**
     * Insert the TLS handlers on both legs. Call from the CLIENT channel's event loop — e.g. the
     * go-ahead write's completion listener — so the client-side SslHandler is in place before the
     * client's ClientHello can arrive, while the plaintext go-ahead is already flushed.
     */
    fun upgrade(clientChannel: Channel, upstreamChannel: Channel) {
        if (!upgraded.compareAndSet(false, true)) return
        val serverCtx = TcpTlsSupport.serverContext(provider, config.upstreamHost)
        clientChannel.pipeline().addFirst("starttls-server-ssl", serverCtx.newHandler(clientChannel.alloc()))
        upstreamChannel.eventLoop().execute {
            val clientCtx = TcpTlsSupport.clientContext(config.upstreamClientAuth)
            upstreamChannel.pipeline().addFirst(
                "starttls-client-ssl",
                clientCtx.newHandler(upstreamChannel.alloc(), config.upstreamHost, config.upstreamPort)
            )
        }
    }
}
