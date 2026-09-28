package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.tls.BurpCertificateProvider
import io.netty.channel.nio.NioEventLoopGroup
import java.util.concurrent.ConcurrentHashMap

class ProxyEngine(
    private val registry: ConnectionRegistry,
    interceptController: InterceptController,
    matchReplaceEngine: MatchReplaceEngine,
    private val certificateProviderSupplier: () -> BurpCertificateProvider?,
    onHeldMessage: (heldMessageId: Long, connectionId: Long, direction: Direction, bytes: ByteArray) -> Unit,
    private val onError: (listenerName: String, message: String) -> Unit
) {
    private val messageGate = MessageGate(registry, interceptController, matchReplaceEngine, onHeldMessage)
    private val bossGroup = NioEventLoopGroup(1)
    private val workerGroup = NioEventLoopGroup()
    private val tcpListeners = ConcurrentHashMap<String, TcpListener>()
    private val udpListeners = ConcurrentHashMap<String, UdpListener>()

    fun startListener(config: ListenerConfig) {
        require(!tcpListeners.containsKey(config.name) && !udpListeners.containsKey(config.name)) {
            "A listener named '${config.name}' is already running"
        }
        try {
            when (config.protocol) {
                Protocol.TCP -> {
                    val listener = TcpListener(config, registry, bossGroup, workerGroup, messageGate, certificateProviderSupplier())
                    listener.start().sync()
                    tcpListeners[config.name] = listener
                }
                Protocol.UDP -> {
                    val listener = UdpListener(config, registry, workerGroup, messageGate)
                    listener.start().sync()
                    udpListeners[config.name] = listener
                }
            }
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: Exception) {
            onError(config.name, e.message ?: "Failed to bind listener")
        }
    }

    fun stopListener(name: String) {
        tcpListeners.remove(name)?.stop()
        udpListeners.remove(name)?.stop()
    }

    fun runningListenerNames(): Set<String> = tcpListeners.keys + udpListeners.keys

    fun shutdown() {
        tcpListeners.values.forEach { it.stop() }
        udpListeners.values.forEach { it.stop() }
        tcpListeners.clear()
        udpListeners.clear()
        workerGroup.shutdownGracefully().sync()
        bossGroup.shutdownGracefully().sync()
    }
}
