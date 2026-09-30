package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.socksx.v5.DefaultSocks5CommandResponse
import io.netty.handler.codec.socksx.v5.DefaultSocks5InitialResponse
import io.netty.handler.codec.socksx.v5.Socks5AuthMethod
import io.netty.handler.codec.socksx.v5.Socks5CommandRequest
import io.netty.handler.codec.socksx.v5.Socks5CommandRequestDecoder
import io.netty.handler.codec.socksx.v5.Socks5CommandStatus
import io.netty.handler.codec.socksx.v5.Socks5CommandType
import io.netty.handler.codec.socksx.v5.Socks5InitialRequest
import io.netty.handler.codec.socksx.v5.Socks5InitialRequestDecoder
import io.netty.handler.codec.socksx.v5.Socks5ServerEncoder

/**
 * A SOCKS5 listener. After the handshake it relays the negotiated destination through
 * the shared [MessageGate] exactly like [TcpListener] — reusing [TcpConnection] and
 * [TcpUpstreamHandler] unchanged by synthesising a per-connection [ListenerConfig] from
 * the negotiated host/port.
 *
 * NOTE: only the CONNECT command is supported (BIND/UDP-ASSOCIATE are rejected), and
 * the handshake is no-auth. TLS MITM on a SOCKS listener is a later addition.
 */
class Socks5Listener(
    private val config: Socks5ListenerConfig,
    private val registry: ConnectionRegistry,
    private val bossGroup: EventLoopGroup,
    private val workerGroup: EventLoopGroup,
    private val messageGate: MessageGate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
) {
    private var boundChannel: Channel? = null

    fun start(): ChannelFuture {
        val bootstrap = ServerBootstrap()
            .group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(ch: SocketChannel) {
                    ch.pipeline().addLast(Socks5ServerEncoder.DEFAULT)
                    ch.pipeline().addLast(Socks5InitialRequestDecoder())
                    ch.pipeline().addLast(InitialHandler())
                }
            })
        val future = bootstrap.bind(config.bindHost, config.bindPort)
        boundChannel = future.channel()
        return future
    }

    fun stop() {
        boundChannel?.close()?.sync()
        boundChannel = null
    }

    /** Answers the greeting with no-auth and swaps in the command decoder. */
    private inner class InitialHandler : SimpleChannelInboundHandler<Socks5InitialRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, msg: Socks5InitialRequest) {
            ctx.pipeline().addAfter(ctx.name(), "socks5-cmd-decoder", Socks5CommandRequestDecoder())
            ctx.pipeline().addAfter("socks5-cmd-decoder", "socks5-cmd-handler", CommandHandler())
            ctx.pipeline().remove(this)
            ctx.writeAndFlush(DefaultSocks5InitialResponse(Socks5AuthMethod.NO_AUTH))
        }
    }

    /** Handles CONNECT: opens the upstream, replies success, then relays. */
    private inner class CommandHandler : SimpleChannelInboundHandler<Socks5CommandRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, req: Socks5CommandRequest) {
            if (req.type() != Socks5CommandType.CONNECT) {
                ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.COMMAND_UNSUPPORTED, req.dstAddrType()))
                    .addListener { ctx.close() }
                return
            }
            val host = req.dstAddr()
            val port = req.dstPort()
            val connConfig = ListenerConfig(config.name, Protocol.TCP, config.bindHost, config.bindPort, host, port)
            val connectionId = registry.openConnection(
                config.name, Protocol.TCP, ctx.channel().remoteAddress().toString(), "$host:$port"
            )
            val connection = TcpConnection(connectionId, connConfig, ctx.channel(), messageGate)
            connection.connectUpstream(workerGroup) { upstream ->
                upstream.pipeline().addLast(TcpUpstreamHandler(registry, connectionId, connection))
            }
            ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.SUCCESS, req.dstAddrType(), host, port))
            // Swap SOCKS negotiation out for a raw relay of client bytes into the connection.
            ctx.pipeline().remove("socks5-cmd-decoder")
            ctx.pipeline().remove(Socks5ServerEncoder::class.java)
            ctx.pipeline().replace(this, "socks5-relay", RelayHandler(connectionId, connection))
        }
    }

    /** Forwards post-handshake client bytes into the relay connection. */
    private inner class RelayHandler(
        private val connectionId: Long,
        private val connection: TcpConnection
    ) : ChannelInboundHandlerAdapter() {
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
}
