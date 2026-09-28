package expedition.engine

import expedition.registry.ConnectionRegistry
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter

class TcpUpstreamHandler(
    private val registry: ConnectionRegistry,
    private val connectionId: Long,
    private val connection: TcpConnection
) : ChannelInboundHandlerAdapter() {
    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        connection.handleUpstreamBytes(msg as ByteBuf)
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
