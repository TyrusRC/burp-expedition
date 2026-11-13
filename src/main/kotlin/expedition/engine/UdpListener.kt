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
    /**
     * Ignored (kept for API compatibility): the listener runs its datagram socket on its OWN
     * single-thread loop, because opening a session blocks briefly on the upstream bind and must
     * not stall the worker loops shared with TCP.
     */
    @Suppress("UNUSED_PARAMETER") group: EventLoopGroup,
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
    private val datagramGroup: EventLoopGroup = io.netty.channel.nio.NioEventLoopGroup(1)

    /** Thrown by [openSession] when the registry's open-connection limit is reached. */
    private class SessionLimitReached : RuntimeException(null, null, false, false)

    fun start(): ChannelFuture {
        val bootstrap = Bootstrap()
            .group(datagramGroup)
            .channel(NioDatagramChannel::class.java)
            .handler(object : SimpleChannelInboundHandler<DatagramPacket>() {
                override fun channelRead0(ctx: ChannelHandlerContext, packet: DatagramPacket) {
                    val clientAddress = packet.sender()
                    val bytes = ByteBufUtil.getBytes(packet.content())
                    val session = try {
                        sessions.sessionFor(clientAddress) { openSession(clientAddress) }
                    } catch (e: SessionLimitReached) {
                        System.err.println("Expedition [${config.name}]: open-connection limit reached; dropping datagram from $clientAddress")
                        return
                    }
                    messageGate.process(session.connectionId, Direction.CLIENT_TO_UPSTREAM, bytes) { finalBytes ->
                        session.channel.writeAndFlush(DatagramPacket(Unpooled.wrappedBuffer(finalBytes), upstreamAddress))
                    }
                }
            })
        val future = bootstrap.bind(config.bindHost, config.bindPort)
        future.addListener { if (!it.isSuccess) { upstreamGroup.shutdownGracefully(); datagramGroup.shutdownGracefully() } }
        clientChannel = future.channel()
        evictionTask = future.channel().eventLoop().scheduleAtFixedRate(
            { evictIdleSessions() }, idleTimeout.toMillis(), idleTimeout.toMillis(), TimeUnit.MILLISECONDS
        )
        return future
    }

    private fun openSession(clientAddress: InetSocketAddress): UdpSession {
        // Same cap as TCP: a spoofed-source flood must not create unbounded sessions/sockets.
        val connectionId = registry.tryOpenConnection(config.name, Protocol.UDP, clientAddress.toString(), upstreamAddress.toString())
            ?: throw SessionLimitReached()
        val upstreamBootstrap = Bootstrap()
            .group(upstreamGroup)
            .channel(NioDatagramChannel::class.java)
            .handler(UdpUpstreamHandler(connectionId, messageGate, clientChannel!!, clientAddress))
        // Safe to await: the upstream channel lives on upstreamGroup, not the datagram
        // loop calling this, so the deadlock guard does not trip. The channel is fully
        // bound before we return, so the first writeAndFlush is not dropped.
        val upstreamChannel = try {
            upstreamBootstrap.bind(0).sync().channel()
        } catch (e: Exception) {
            registry.closeConnection(connectionId)
            messageGate.detachConnection(connectionId)
            throw e
        }
        return UdpSession(connectionId, upstreamChannel)
    }

    /** Same cleanup as a closing TCP connection: close socket, close registry entry, release held state. */
    private fun releaseSession(session: UdpSession) {
        session.channel.close()
        registry.closeConnection(session.connectionId)
        messageGate.detachConnection(session.connectionId)
    }

    private fun evictIdleSessions() {
        sessions.evictIdle { _, session -> releaseSession(session) }
    }

    fun stop() {
        evictionTask?.cancel(false)
        clientChannel?.close()?.sync()
        sessions.drainAll { _, session -> releaseSession(session) }
        upstreamGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS).sync()
        datagramGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS).sync()
        clientChannel = null
    }
}
