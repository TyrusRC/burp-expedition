package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.session.UdpSessionTable
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.EventLoopGroup
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import java.net.InetSocketAddress
import java.time.Duration
import java.util.concurrent.TimeUnit

class UdpListener(
    private val config: ListenerConfig,
    private val registry: ConnectionRegistry,
    private val group: EventLoopGroup,
    private val messageGate: MessageGate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> },
    private val idleTimeout: Duration = Duration.ofMinutes(2)
) {
    init {
        require(config.tlsMode == TlsMode.NONE) { "TLS MITM is not supported for UDP listeners in v1" }
    }

    private var clientChannel: Channel? = null
    private val upstreamAddress = InetSocketAddress(config.upstreamHost, config.upstreamPort)
    private val sessions = UdpSessionTable<UdpSession>(idleTimeout)
    private var evictionTask: io.netty.util.concurrent.ScheduledFuture<*>? = null

    // Upstream sockets bind on their own group so openSession can await the bind
    // (write-after-bind ordering — an unbound datagram channel silently drops the first
    // write) without hitting Netty's deadlock guard: openSession runs on `group`'s
    // datagram event-loop thread, and awaiting a future on a DIFFERENT group's loop is safe.
    private val upstreamGroup: EventLoopGroup = io.netty.channel.nio.NioEventLoopGroup(1)

    fun start(): ChannelFuture {
        val bootstrap = Bootstrap()
            .group(group)
            .channel(NioDatagramChannel::class.java)
            .handler(object : SimpleChannelInboundHandler<DatagramPacket>() {
                override fun channelRead0(ctx: ChannelHandlerContext, packet: DatagramPacket) {
                    val clientAddress = packet.sender()
                    val bytes = ByteBufUtil.getBytes(packet.content())
                    val session = sessions.sessionFor(clientAddress) { openSession(clientAddress) }
                    messageGate.process(session.connectionId, Direction.CLIENT_TO_UPSTREAM, bytes) { finalBytes ->
                        session.channel.writeAndFlush(DatagramPacket(Unpooled.wrappedBuffer(finalBytes), upstreamAddress))
                    }
                }
            })
        val future = bootstrap.bind(config.bindHost, config.bindPort)
        clientChannel = future.channel()
        evictionTask = future.channel().eventLoop().scheduleAtFixedRate(
            { evictIdleSessions() }, idleTimeout.toMillis(), idleTimeout.toMillis(), TimeUnit.MILLISECONDS
        )
        return future
    }

    private fun openSession(clientAddress: InetSocketAddress): UdpSession {
        val connectionId = registry.openConnection(config.name, Protocol.UDP, clientAddress.toString(), upstreamAddress.toString())
        val upstreamBootstrap = Bootstrap()
            .group(upstreamGroup)
            .channel(NioDatagramChannel::class.java)
            .handler(UdpUpstreamHandler(connectionId, messageGate, clientChannel!!, clientAddress))
        // Safe to await: the upstream channel lives on upstreamGroup, not the datagram
        // loop calling this, so the deadlock guard does not trip. The channel is fully
        // bound before we return, so the first writeAndFlush is not dropped.
        val upstreamChannel = upstreamBootstrap.bind(0).sync().channel()
        return UdpSession(connectionId, upstreamChannel)
    }

    private fun evictIdleSessions() {
        sessions.evictIdle { _, session ->
            session.channel.close()
            registry.closeConnection(session.connectionId)
        }
    }

    fun stop() {
        evictionTask?.cancel(false)
        clientChannel?.close()?.sync()
        sessions.drainAll { _, session ->
            session.channel.close()
            registry.closeConnection(session.connectionId)
        }
        upstreamGroup.shutdownGracefully().sync()
        clientChannel = null
    }
}
