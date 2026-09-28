package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
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
    private val messageGate: MessageGate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
) {
    private var boundChannel: Channel? = null

    fun start(): ChannelFuture {
        val bootstrap = ServerBootstrap()
            .group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(clientChannel: SocketChannel) {
                    clientChannel.pipeline().addLast(
                        TcpClientHandler(config, registry, workerGroup, messageGate) { upstream, connection ->
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
