package expedition.engine

import expedition.pipeline.MessageGate
import expedition.registry.Direction
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.DatagramPacket
import java.net.InetSocketAddress

class UdpUpstreamHandler(
    private val connectionId: Long,
    private val messageGate: MessageGate,
    private val clientChannel: Channel,
    private val clientAddress: InetSocketAddress
) : SimpleChannelInboundHandler<DatagramPacket>() {

    override fun channelRead0(ctx: ChannelHandlerContext, packet: DatagramPacket) {
        val bytes = ByteBufUtil.getBytes(packet.content())
        messageGate.process(connectionId, Direction.UPSTREAM_TO_CLIENT, bytes) { finalBytes ->
            clientChannel.writeAndFlush(DatagramPacket(Unpooled.wrappedBuffer(finalBytes), clientAddress))
        }
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        // NOTE: UDP has no reliable per-datagram failure signal (e.g. ICMP
        // port-unreachable surfaces here asynchronously). Intentionally left as a
        // no-op: keep this session alive rather than tearing down the session table
        // entry — other sessions on this listener are unaffected either way since
        // each client gets its own dedicated upstream channel (see UdpListener).
    }
}
