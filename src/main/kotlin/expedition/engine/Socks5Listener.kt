package expedition.engine

import expedition.engine.tls.SniTlsRouter
import expedition.engine.tls.TlsDecision
import expedition.engine.tls.TlsPassthroughMatcher
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import expedition.tls.BurpCertificateProvider
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.socksx.v5.DefaultSocks5CommandResponse
import io.netty.handler.codec.socksx.v5.DefaultSocks5InitialResponse
import io.netty.handler.codec.socksx.v5.DefaultSocks5PasswordAuthResponse
import io.netty.handler.codec.socksx.v5.Socks5AuthMethod
import io.netty.handler.codec.socksx.v5.Socks5CommandRequest
import io.netty.handler.codec.socksx.v5.Socks5CommandRequestDecoder
import io.netty.handler.codec.socksx.v5.Socks5CommandStatus
import io.netty.handler.codec.socksx.v5.Socks5CommandType
import io.netty.handler.codec.socksx.v5.Socks5InitialRequest
import io.netty.handler.codec.socksx.v5.Socks5InitialRequestDecoder
import io.netty.handler.codec.socksx.v5.Socks5PasswordAuthRequest
import io.netty.handler.codec.socksx.v5.Socks5PasswordAuthRequestDecoder
import io.netty.handler.codec.socksx.v5.Socks5PasswordAuthStatus
import io.netty.handler.codec.socksx.v5.Socks5ServerEncoder
import io.netty.handler.proxy.ProxyConnectException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.UnknownHostException
import java.security.MessageDigest

/**
 * A SOCKS5 listener. After the handshake it relays the negotiated destination through
 * the shared [MessageGate] exactly like [TcpListener] — reusing [TcpConnection] and
 * [TcpUpstreamHandler] by synthesising a per-connection [ListenerConfig] from the
 * negotiated host/port plus the listener's TLS mode / upstream proxy / passthrough list.
 *
 * The CONNECT reply is sent only after the upstream (and any chained proxy tunnel) is
 * established; a failed connect is answered with the matching SOCKS5 error code.
 * With TLS MITM the SNI router sits in front of the relay once the tunnel is up.
 *
 * NOTE: only the CONNECT command is supported (BIND/UDP-ASSOCIATE are rejected).
 */
class Socks5Listener(
    private val config: Socks5ListenerConfig,
    private val registry: ConnectionRegistry,
    private val bossGroup: EventLoopGroup,
    private val workerGroup: EventLoopGroup,
    private val messageGate: MessageGate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> },
    private val certificateProvider: BurpCertificateProvider? = null
) {
    private var boundChannel: Channel? = null
    private val passthrough = TlsPassthroughMatcher(config.tlsPassthrough)

    fun start(): ChannelFuture {
        requireCertificateProvider(config.name, config.tlsMode, certificateProvider)
        val bootstrap = ServerBootstrap()
            .group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(ch: SocketChannel) {
                    children.add(ch)
                    ch.pipeline().addLast(Socks5ServerEncoder.DEFAULT)
                    ch.pipeline().addLast(INITIAL_DECODER, Socks5InitialRequestDecoder())
                    ch.pipeline().addLast(InitialHandler())
                }
            })
        val future = bootstrap.bind(config.bindHost, config.bindPort)
        boundChannel = future.channel()
        return future
    }

    /** Accepted client channels (closed ones drop out automatically); closed on [stop]. */
    private val children = io.netty.channel.group.DefaultChannelGroup(io.netty.util.concurrent.GlobalEventExecutor.INSTANCE)

    /** Live client connections of this listener. */
    fun openChildCount(): Int = children.size

    /** Unbinds AND closes this listener's open connections (their upstream legs follow). */
    fun stop() {
        boundChannel?.close()?.sync()
        boundChannel = null
        children.close().awaitUninterruptibly(5, java.util.concurrent.TimeUnit.SECONDS)
    }

    /** Negotiates the auth method (no-auth by default, RFC 1929 user/pass when configured). */
    private inner class InitialHandler : SimpleChannelInboundHandler<Socks5InitialRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, msg: Socks5InitialRequest) {
            if (config.requiresAuth) {
                if (Socks5AuthMethod.PASSWORD !in msg.authMethods()) {
                    ctx.writeAndFlush(DefaultSocks5InitialResponse(Socks5AuthMethod.UNACCEPTED))
                        .addListener(ChannelFutureListener.CLOSE)
                    return
                }
                ctx.pipeline().replace(INITIAL_DECODER, AUTH_DECODER, Socks5PasswordAuthRequestDecoder())
                ctx.pipeline().replace(this, "socks5-auth-handler", PasswordAuthHandler())
                ctx.writeAndFlush(DefaultSocks5InitialResponse(Socks5AuthMethod.PASSWORD))
                return
            }
            ctx.pipeline().replace(INITIAL_DECODER, CMD_DECODER, Socks5CommandRequestDecoder())
            ctx.pipeline().replace(this, CMD_HANDLER, CommandHandler())
            ctx.writeAndFlush(DefaultSocks5InitialResponse(Socks5AuthMethod.NO_AUTH))
        }
    }

    /** RFC 1929 sub-negotiation. */
    private inner class PasswordAuthHandler : SimpleChannelInboundHandler<Socks5PasswordAuthRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, req: Socks5PasswordAuthRequest) {
            val ok = constantTimeEquals(req.username(), config.username ?: "") &&
                constantTimeEquals(req.password(), config.password ?: "")
            if (!ok) {
                ctx.writeAndFlush(DefaultSocks5PasswordAuthResponse(Socks5PasswordAuthStatus.FAILURE))
                    .addListener(ChannelFutureListener.CLOSE)
                return
            }
            ctx.pipeline().replace(AUTH_DECODER, CMD_DECODER, Socks5CommandRequestDecoder())
            ctx.pipeline().replace(this, CMD_HANDLER, CommandHandler())
            ctx.writeAndFlush(DefaultSocks5PasswordAuthResponse(Socks5PasswordAuthStatus.SUCCESS))
        }
    }

    /** Handles CONNECT: opens the upstream, replies once connected (or with an error), then relays. */
    private inner class CommandHandler : SimpleChannelInboundHandler<Socks5CommandRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, req: Socks5CommandRequest) {
            if (req.type() != Socks5CommandType.CONNECT) {
                ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.COMMAND_UNSUPPORTED, req.dstAddrType()))
                    .addListener(ChannelFutureListener.CLOSE)
                return
            }
            val host = req.dstAddr()
            val port = req.dstPort()
            val connConfig = ListenerConfig(
                config.name, Protocol.TCP, config.bindHost, config.bindPort, host, port,
                tlsMode = config.tlsMode,
                upstreamClientAuth = config.upstreamClientAuth,
                upstreamProxy = config.upstreamProxy,
                tlsPassthrough = config.tlsPassthrough
            )
            val connectionId = registry.tryOpenConnection(
                config.name, Protocol.TCP, ctx.channel().remoteAddress().toString(), "$host:$port"
            ) ?: run {
                ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.FAILURE, req.dstAddrType()))
                    .addListener(ChannelFutureListener.CLOSE)
                return
            }
            val connection = TcpConnection(connectionId, connConfig, ctx.channel(), messageGate)
            val handler = this
            // Reply SUCCESS, swap the SOCKS codecs for the relay (+ SNI router under MITM). Runs on
            // the client loop; the reply is encoded synchronously, so no read can interleave.
            fun wireRelay() {
                ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.SUCCESS, req.dstAddrType(), host, port))
                ctx.pipeline().remove(CMD_DECODER)
                ctx.pipeline().remove(Socks5ServerEncoder::class.java)
                ctx.pipeline().replace(handler, RELAY_HANDLER, RelayHandler(connectionId, connection))
                if (config.tlsMode == TlsMode.MITM) {
                    ctx.pipeline().addBefore(RELAY_HANDLER, SniTlsRouter.NAME,
                        SniTlsRouter(certificateProvider!!, host, passthrough,
                            onMitmHandshake = { registry.markTls(connectionId) }) { _, decision ->
                            when (decision) {
                                is TlsDecision.Passthrough -> { connection.enterPassthrough(decision.sni); connection.dialNow(); null }
                                is TlsDecision.Mitm -> connection.startUpstreamTls(
                                    decision.sni ?: host,
                                    if (connection.isLazy) expedition.engine.tls.TcpTlsSupport.http11Only(decision.alpn)
                                    else messageGate.mitmAlpn(config.name, decision.alpn)
                                ).takeUnless { connection.isLazy }
                            }
                        })
                }
                ctx.channel().config().isAutoRead = true
            }
            val upstreamBuilder: (io.netty.channel.socket.SocketChannel) -> Unit = { upstream ->
                upstream.pipeline().addLast(TcpConnection.UPSTREAM_HANDLER, TcpUpstreamHandler(registry, connectionId, connection))
            }
            // Nothing should arrive before our reply; don't read until the relay is wired.
            ctx.channel().config().isAutoRead = false
            if (messageGate.wantsLazyDial(config.name)) {
                // Active mock rule: answer SUCCESS now and dial only when a request must really go
                // upstream — a mocked host need not exist. A failed dial then fails that request
                // (502 for HTTP) instead of the SOCKS handshake.
                connection.deferDial {
                    connection.connectUpstreamLazily(workerGroup) { upstream ->
                        connection.installLazyUpstreamTls(upstream)
                        upstreamBuilder(upstream)
                    }
                }
                if (config.tlsMode == TlsMode.NONE) connection.dialIfClientSilent()
                wireRelay()
                return
            }
            connection.connectUpstream(workerGroup, onConnectResult = { cause ->
                ctx.channel().eventLoop().execute {
                    if (cause != null) {
                        val status = socksStatusFor(cause)
                        registry.closeConnection(connectionId)
                        if (ctx.channel().isActive) {
                            ctx.writeAndFlush(DefaultSocks5CommandResponse(status, req.dstAddrType()))
                                .addListener { connection.close() }
                        } else connection.close()
                        return@execute
                    }
                    if (!ctx.channel().isActive) { connection.close(); return@execute }
                    wireRelay()
                }
            }, upstreamBuilder)
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

    companion object {
        private const val INITIAL_DECODER = "socks5-initial-decoder"
        private const val AUTH_DECODER = "socks5-auth-decoder"
        private const val CMD_DECODER = "socks5-cmd-decoder"
        private const val CMD_HANDLER = "socks5-cmd-handler"
        private const val RELAY_HANDLER = "socks5-relay"

        /** Map an upstream connect failure to the RFC 1928 reply code. */
        fun socksStatusFor(cause: Throwable?): Socks5CommandStatus {
            var c: Throwable? = cause
            while (c != null) {
                val msg = c.message?.lowercase() ?: ""
                when {
                    // Before ConnectException: ProxyConnectException is a subclass.
                    c is ProxyConnectException -> return Socks5CommandStatus.FAILURE
                    c is UnknownHostException || c is NoRouteToHostException -> return Socks5CommandStatus.HOST_UNREACHABLE
                    c is io.netty.channel.ConnectTimeoutException -> return Socks5CommandStatus.HOST_UNREACHABLE
                    c is ConnectException && "refused" in msg -> return Socks5CommandStatus.CONNECTION_REFUSED
                    c is ConnectException && "network is unreachable" in msg -> return Socks5CommandStatus.NETWORK_UNREACHABLE
                    c is ConnectException && ("unreachable" in msg || "no route" in msg || "timed out" in msg) ->
                        return Socks5CommandStatus.HOST_UNREACHABLE
                }
                c = c.cause.takeIf { it !== c }
            }
            return Socks5CommandStatus.FAILURE
        }

        private fun constantTimeEquals(a: String?, b: String): Boolean =
            MessageDigest.isEqual((a ?: "").toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
    }
}
