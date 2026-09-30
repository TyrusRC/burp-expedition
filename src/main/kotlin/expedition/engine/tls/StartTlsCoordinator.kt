package expedition.engine.tls

import expedition.engine.ListenerConfig
import expedition.engine.StartTlsDetector
import expedition.tls.BurpCertificateProvider
import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter

/**
 * Drives a plaintext→TLS (STARTTLS) upgrade on a live relay. Two observer handlers feed
 * the [StartTlsDetector] the plaintext of each direction; when the server's go-ahead is
 * seen, the SslHandlers are inserted on both legs — the go-ahead itself has already been
 * written to the client in plaintext by the time the (event-loop-scheduled) insertion runs,
 * so the record boundary is respected.
 *
 * NOTE: assumes the STARTTLS negotiation is not being held in the interceptor (the norm —
 * you intercept application data, not the handshake). One upgrade per connection.
 */
class StartTlsCoordinator(
    val detector: StartTlsDetector,
    private val clientChannel: Channel,
    private val provider: BurpCertificateProvider,
    private val config: ListenerConfig
) {
    @Volatile private var upgraded = false

    fun clientObserver(): ChannelInboundHandlerAdapter = object : ChannelInboundHandlerAdapter() {
        override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
            if (!upgraded && msg is ByteBuf) detector.onClientData(ByteBufUtil.getBytes(msg))
            ctx.fireChannelRead(msg)
        }
    }

    fun upstreamObserver(): ChannelInboundHandlerAdapter = object : ChannelInboundHandlerAdapter() {
        override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
            val trigger = !upgraded && msg is ByteBuf && detector.onUpstreamData(ByteBufUtil.getBytes(msg))
            ctx.fireChannelRead(msg)
            if (trigger) upgrade(ctx.channel())
        }
    }

    private fun upgrade(upstreamChannel: Channel) {
        if (upgraded) return
        upgraded = true
        // Client leg: terminate the client's TLS with a Burp-CA-signed leaf.
        clientChannel.eventLoop().execute {
            val serverCtx = TcpTlsSupport.serverContext(provider, config.upstreamHost)
            clientChannel.pipeline().addFirst("starttls-server-ssl", serverCtx.newHandler(clientChannel.alloc()))
        }
        // Upstream leg: open TLS to the real server.
        upstreamChannel.eventLoop().execute {
            val clientCtx = TcpTlsSupport.clientContext(config.upstreamClientAuth)
            upstreamChannel.pipeline().addFirst(
                "starttls-client-ssl",
                clientCtx.newHandler(upstreamChannel.alloc(), config.upstreamHost, config.upstreamPort)
            )
        }
    }
}
