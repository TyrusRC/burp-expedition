package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

class UdpEchoServer : AutoCloseable {
    private val socket = DatagramSocket(0)
    val port: Int get() = socket.localPort
    @Volatile private var running = true
    private val thread = Thread {
        val buffer = ByteArray(4096)
        while (running) {
            val packet = DatagramPacket(buffer, buffer.size)
            try { socket.receive(packet) } catch (e: Exception) { break }
            socket.send(DatagramPacket(packet.data, packet.length, packet.socketAddress))
        }
    }.apply { isDaemon = true; start() }

    override fun close() {
        running = false
        socket.close()
    }
}

class UdpListenerTest {

    private fun startedPort(listener: UdpListener) =
        (listener.start().sync().channel().localAddress() as InetSocketAddress).port

    @Test
    fun `relays datagrams between client and upstream and records them`() {
        val group = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        UdpEchoServer().use { echo ->
            val config = ListenerConfig("u1", Protocol.UDP, "127.0.0.1", 0, "127.0.0.1", echo.port)
            val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
            val listener = UdpListener(config, registry, group, gate)
            try {
                val port = startedPort(listener)
                DatagramSocket().use { client ->
                    val message = "ping".toByteArray()
                    client.send(DatagramPacket(message, message.size, InetSocketAddress("127.0.0.1", port)))
                    val response = ByteArray(4)
                    val packet = DatagramPacket(response, response.size)
                    client.soTimeout = 2000
                    client.receive(packet)
                    assertEquals("ping", String(response))
                }
                waitUntil { registry.allMessages().size >= 2 }
            } finally {
                listener.stop()
            }
        }
        group.shutdownGracefully().sync()
    }

    @Test
    fun `applies match and replace rules to datagrams`() {
        val group = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val matchReplace = MatchReplaceEngine().apply { addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar")) }
        UdpEchoServer().use { echo ->
            val config = ListenerConfig("u2", Protocol.UDP, "127.0.0.1", 0, "127.0.0.1", echo.port)
            val gate = MessageGate(registry, InterceptController(), matchReplace) { _, _, _, _ -> }
            val listener = UdpListener(config, registry, group, gate)
            try {
                val port = startedPort(listener)
                DatagramSocket().use { client ->
                    val message = "foo".toByteArray()
                    client.send(DatagramPacket(message, message.size, InetSocketAddress("127.0.0.1", port)))
                    val response = ByteArray(3)
                    val packet = DatagramPacket(response, response.size)
                    client.soTimeout = 2000
                    client.receive(packet)
                    assertEquals("bar", String(response))
                }
            } finally {
                listener.stop()
            }
        }
        group.shutdownGracefully().sync()
    }

    @Test
    fun `a failing session does not affect a concurrent working session`() {
        val group = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val deadPort = DatagramSocket(0).use { it.localPort }
        UdpEchoServer().use { echo ->
            val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
            val deadListener = UdpListener(ListenerConfig("u3-dead", Protocol.UDP, "127.0.0.1", 0, "127.0.0.1", deadPort), registry, group, gate)
            val liveListener = UdpListener(ListenerConfig("u3-live", Protocol.UDP, "127.0.0.1", 0, "127.0.0.1", echo.port), registry, group, gate)
            try {
                val deadPortBound = startedPort(deadListener)
                val livePortBound = startedPort(liveListener)

                DatagramSocket().use { client ->
                    client.send(DatagramPacket(ByteArray(1) { 1 }, 1, InetSocketAddress("127.0.0.1", deadPortBound)))
                }
                DatagramSocket().use { client ->
                    val message = "ok".toByteArray()
                    client.send(DatagramPacket(message, message.size, InetSocketAddress("127.0.0.1", livePortBound)))
                    val response = ByteArray(2)
                    val packet = DatagramPacket(response, response.size)
                    client.soTimeout = 2000
                    client.receive(packet)
                    assertEquals("ok", String(response))
                }
            } finally {
                deadListener.stop()
                liveListener.stop()
            }
        }
        group.shutdownGracefully().sync()
    }
}
