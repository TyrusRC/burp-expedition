package expedition.engine

import expedition.engine.tls.SniTlsRouter
import expedition.engine.tls.StartTlsCoordinator
import expedition.engine.tls.TcpTlsSupport
import expedition.engine.tls.TlsDecision
import expedition.engine.tls.TlsPassthroughMatcher
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.tls.BurpCertificateProvider
import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel

class TcpListener(
    private val config: ListenerConfig,
    private val registry: ConnectionRegistry,
    private val bossGroup: EventLoopGroup,
    private val workerGroup: EventLoopGroup,
    private val messageGate: MessageGate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> },
    private val certificateProvider: BurpCertificateProvider? = null
) {
    private var boundChannel: Channel? = null

    fun start(): ChannelFuture {
        // Fail fast at bind time rather than per connection inside initChannel.
        val provider = requireCertificateProvider(config.name, config.tlsMode, certificateProvider)
        val passthrough = TlsPassthroughMatcher(config.tlsPassthrough)
        val bootstrap = ServerBootstrap()
            .group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(clientChannel: SocketChannel) {
                    children.add(clientChannel)
                    // STARTTLS: start plaintext; detection + upgrade run inside the relay (post-gate).
                    val startTls = if (config.tlsMode == TlsMode.STARTTLS) StartTlsCoordinator(StartTlsDetector(), provider!!, config) { registry.markTls(it) } else null
                    val mitm = config.tlsMode == TlsMode.MITM
                    // MITM: the upstream is dialled only once the ClientHello's SNI is known, so it can be
                    // relayed raw (passthrough) or TLS'd with the client's SNI.
                    val clientHandler = TcpClientHandler(config, registry, workerGroup, messageGate, startTls, deferUpstreamConnect = mitm) { upstream, connection ->
                        upstream.pipeline().addLast(TcpConnection.UPSTREAM_HANDLER, TcpUpstreamHandler(registry, connection.connectionId, connection))
                    }
                    if (mitm) {
                        clientChannel.pipeline().addLast(SniTlsRouter.NAME, SniTlsRouter(provider!!, config.upstreamHost, passthrough,
                            onMitmHandshake = { registry.markTls(clientHandler.connection.connectionId) }) { _, decision ->
                            val conn = clientHandler.connection
                            when (decision) {
                                is TlsDecision.Passthrough -> {
                                    conn.enterPassthrough(decision.sni)
                                    if (conn.isLazy) conn.dialNow() else clientHandler.connectUpstream()
                                    null
                                }
                                is TlsDecision.Mitm -> {
                                    val peer = decision.sni ?: config.upstreamHost
                                    if (conn.isLazy) {
                                        // No upstream yet (mock rules): settle on http/1.1 deliberately.
                                        conn.startUpstreamTls(peer, TcpTlsSupport.http11Only(decision.alpn))
                                        null
                                    } else {
                                        // Active rules: http/1.1 only (rules need HTTP/1.x). No rules: the
                                        // client's list; the client side then selects whatever the
                                        // upstream picked (h2 relayed as bytes).
                                        val alpn = messageGate.mitmAlpn(config.name, decision.alpn)
                                        val result = if (alpn.isNotEmpty()) conn.newAlpnPromise() else null
                                        clientHandler.connectUpstream { upstream ->
                                            upstream.pipeline().addLast(
                                                TcpConnection.UPSTREAM_SSL_HANDLER,
                                                conn.upstreamTlsHandler(upstream, peer, alpn, result)
                                            )
                                        }
                                        result
                                    }
                                }
                            }
                        })
                    }
                    clientChannel.pipeline().addLast(clientHandler)
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
}

/** Throws a clear error if [mode] needs a CA (MITM / STARTTLS) but none is configured. */
internal fun requireCertificateProvider(listenerName: String, mode: TlsMode, provider: BurpCertificateProvider?): BurpCertificateProvider? {
    if (mode != TlsMode.NONE && provider == null) {
        throw IllegalStateException(
            "Listener '$listenerName' uses TLS mode $mode but no CA certificate provider (Burp CA keystore) is configured"
        )
    }
    return provider
}
