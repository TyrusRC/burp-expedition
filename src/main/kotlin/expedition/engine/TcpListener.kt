package expedition.engine

import expedition.engine.tls.TcpTlsSupport
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
        val bootstrap = ServerBootstrap()
            .group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(clientChannel: SocketChannel) {
                    if (config.tlsMode == TlsMode.MITM) {
                        val provider = certificateProvider
                            ?: throw IllegalStateException("Listener '${config.name}' requires TLS but no BurpCertificateProvider was configured")
                        val serverSslContext = TcpTlsSupport.serverContext(provider, config.upstreamHost)
                        clientChannel.pipeline().addLast(serverSslContext.newHandler(clientChannel.alloc()))
                    }
                    clientChannel.pipeline().addLast(
                        TcpClientHandler(config, registry, workerGroup, messageGate) { upstream, connection ->
                            if (config.tlsMode == TlsMode.MITM) {
                                val clientSslContext = TcpTlsSupport.clientContext(config.upstreamClientAuth)
                                upstream.pipeline().addLast(clientSslContext.newHandler(upstream.alloc(), config.upstreamHost, config.upstreamPort))
                            }
                            upstream.pipeline().addLast(TcpUpstreamHandler(registry, connection.connectionId, connection))
                        }
                    )
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
}
