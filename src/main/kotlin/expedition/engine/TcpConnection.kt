package expedition.engine

import expedition.engine.tls.StartTlsCoordinator
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
    private val messageGate: MessageGate,
    private val startTls: StartTlsCoordinator? = null
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
                override fun initChannel(upstream: SocketChannel) {
                    // Chain the upstream leg through an outbound SOCKS5 proxy if configured.
                    // The ProxyHandler negotiates to the real destination (the bootstrap's
                    // connect target) and buffers writes until the tunnel is established.
                    config.upstreamProxy?.let { p ->
                        upstream.pipeline().addLast(
                            io.netty.handler.proxy.Socks5ProxyHandler(java.net.InetSocketAddress(p.host, p.port))
                        )
                    }
                    pipelineBuilder(upstream)
                }
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
            // Mark the STARTTLS request BEFORE writing upstream, so the flag is set before the
            // server's go-ahead can race back (loopback is fast enough to lose that ordering).
            startTls?.onClientForwarded(finalBytes)
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
            val up = upstreamChannel
            if (startTls != null && up != null && startTls.isGoAhead(finalBytes)) {
                // Write the go-ahead AND insert the TLS handlers in one client-loop task: the 220
                // traverses the pipeline (plaintext) before addFirst, and no client read (the
                // ClientHello) can interleave — so the SslHandler is always in place first.
                clientChannel.eventLoop().execute {
                    clientChannel.writeAndFlush(Unpooled.wrappedBuffer(finalBytes))
                    startTls.upgrade(clientChannel, up)
                }
            } else {
                clientChannel.writeAndFlush(Unpooled.wrappedBuffer(finalBytes))
            }
        }
    }

    fun close() {
        if (closed) return
        closed = true
        synchronized(pendingWrites) {
            pendingWrites.forEach { it.release() }   // release any never-flushed buffers
            pendingWrites.clear()
        }
        clientChannel.close()
        upstreamChannel?.close()
    }
}
