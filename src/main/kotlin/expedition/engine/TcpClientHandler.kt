package expedition.engine

import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.SocketChannel

class TcpClientHandler(
    private val config: ListenerConfig,
    private val registry: ConnectionRegistry,
    private val workerGroup: EventLoopGroup,
    private val messageGate: MessageGate,
    private val startTls: expedition.engine.tls.StartTlsCoordinator? = null,
    /**
     * When true the upstream is NOT dialled in channelActive; the owner calls [connectUpstream]
     * later (MITM waits for the ClientHello's SNI to pick passthrough vs. TLS and the upstream SNI).
     */
    private val deferUpstreamConnect: Boolean = false,
    private val upstreamPipelineBuilder: (SocketChannel, TcpConnection) -> Unit
) : ChannelInboundHandlerAdapter() {
    lateinit var connection: TcpConnection
        private set
    private var connectionId: Long = -1

    override fun channelActive(ctx: ChannelHandlerContext) {
        connectionId = registry.tryOpenConnection(
            config.name, Protocol.TCP, ctx.channel().remoteAddress().toString(),
            "${config.upstreamHost}:${config.upstreamPort}"
        ) ?: run {
            System.err.println("Expedition [${config.name}]: open-connection limit reached; refusing ${ctx.channel().remoteAddress()}")
            ctx.close()
            return
        }
        connection = TcpConnection(connectionId, config, ctx.channel(), messageGate, startTls)
        if (config.tlsMode != TlsMode.STARTTLS && messageGate.wantsLazyDial(config.name)) {
            // An active mock rule may answer without any upstream: dial only when a request
            // actually has to be forwarded (a dead upstream then fails just that request).
            connection.deferDial(::connectUpstreamLazily)
            // Server-speaks-first protocols would wait forever for a banner: dial anyway if the
            // client stays silent. (TLS MITM is always client-first.)
            if (config.tlsMode == TlsMode.NONE) connection.dialIfClientSilent()
        } else if (!deferUpstreamConnect) {
            connectUpstream()
        }
    }

    private fun connectUpstreamLazily() {
        connection.connectUpstreamLazily(workerGroup) { upstream ->
            connection.installLazyUpstreamTls(upstream)
            upstreamPipelineBuilder(upstream, connection)
        }
    }

    /** Dial the upstream; [extraBuilder] runs before the default upstream pipeline builder. */
    fun connectUpstream(extraBuilder: (SocketChannel) -> Unit = {}) {
        connection.connectUpstream(workerGroup) { upstream ->
            extraBuilder(upstream)
            upstreamPipelineBuilder(upstream, connection)
        }
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (!::connection.isInitialized) { io.netty.util.ReferenceCountUtil.release(msg); return }
        connection.handleClientBytes(msg as ByteBuf)
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        if (!::connection.isInitialized) return
        registry.closeConnection(connectionId)
        connection.close()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        if (!::connection.isInitialized) { ctx.close(); return }
        registry.closeConnection(connectionId)
        connection.close()
    }
}
