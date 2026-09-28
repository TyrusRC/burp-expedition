package expedition.engine

import expedition.pipeline.MessageGate
import expedition.registry.Direction
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import java.util.Collections

class TcpConnection(
    val connectionId: Long,
    private val config: ListenerConfig,
    private val clientChannel: Channel,
    private val messageGate: MessageGate
) {
    @Volatile private var upstreamChannel: Channel? = null
    @Volatile private var upstreamReady = false
    private val pendingWrites = Collections.synchronizedList(mutableListOf<ByteBuf>())
    @Volatile private var closed = false

    fun connectUpstream(workerGroup: EventLoopGroup, pipelineBuilder: (SocketChannel) -> Unit) {
        val bootstrap = Bootstrap()
            .group(workerGroup)
            .channel(NioSocketChannel::class.java)
            .handler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(upstream: SocketChannel) = pipelineBuilder(upstream)
            })
        bootstrap.connect(config.upstreamHost, config.upstreamPort).addListener(ChannelFutureListener { f ->
            if (f.isSuccess) {
                upstreamChannel = f.channel()
                synchronized(pendingWrites) {
                    pendingWrites.forEach { upstreamChannel!!.writeAndFlush(it) }
                    pendingWrites.clear()
                    upstreamReady = true
                }
            } else {
                close()
            }
        })
    }

    fun handleClientBytes(buf: ByteBuf) {
        val bytes = ByteBufUtil.getBytes(buf)
        buf.release()
        messageGate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, bytes) { finalBytes ->
            val outBuf = Unpooled.wrappedBuffer(finalBytes)
            synchronized(pendingWrites) {
                if (upstreamReady) upstreamChannel!!.writeAndFlush(outBuf) else pendingWrites.add(outBuf)
            }
        }
    }

    fun handleUpstreamBytes(buf: ByteBuf) {
        val bytes = ByteBufUtil.getBytes(buf)
        buf.release()
        messageGate.process(connectionId, Direction.UPSTREAM_TO_CLIENT, bytes) { finalBytes ->
            clientChannel.writeAndFlush(Unpooled.wrappedBuffer(finalBytes))
        }
    }

    fun close() {
        if (closed) return
        closed = true
        clientChannel.close()
        upstreamChannel?.close()
    }
}
