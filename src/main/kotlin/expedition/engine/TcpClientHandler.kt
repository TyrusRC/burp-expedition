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
    private val upstreamPipelineBuilder: (SocketChannel, TcpConnection) -> Unit
) : ChannelInboundHandlerAdapter() {
    private lateinit var connection: TcpConnection
    private var connectionId: Long = -1

    override fun channelActive(ctx: ChannelHandlerContext) {
        connectionId = registry.openConnection(
            config.name, Protocol.TCP, ctx.channel().remoteAddress().toString(),
            "${config.upstreamHost}:${config.upstreamPort}"
        )
        connection = TcpConnection(connectionId, config, ctx.channel(), messageGate)
        connection.connectUpstream(workerGroup) { upstream -> upstreamPipelineBuilder(upstream, connection) }
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        connection.handleClientBytes(msg as ByteBuf)
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        registry.closeConnection(connectionId)
        connection.close()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        registry.closeConnection(connectionId)
        connection.close()
    }
}
