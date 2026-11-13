package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import io.netty.buffer.Unpooled
import io.netty.channel.embedded.EmbeddedChannel
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.Socket

class ConnectionLimitsTest {

    @Test
    fun `pending upstream writes are capped and overflow closes the connection with a warning`() {
        val registry = ConnectionRegistry()
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
        val client = EmbeddedChannel()
        val id = registry.openConnection("cap", Protocol.TCP, "c", "u")
        val config = ListenerConfig("cap", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", 1)
        // Upstream never connected: everything goes to the pending queue.
        val conn = TcpConnection(id, config, client, gate, maxPendingBytes = 10)
        conn.handleClientBytes(Unpooled.wrappedBuffer(ByteArray(8)))
        assertTrue(client.isOpen)
        conn.handleClientBytes(Unpooled.wrappedBuffer(ByteArray(8)))
        waitUntil { !client.isOpen }
        assertTrue(registry.messagesFor(id).any { it.dissectedView?.contains("pending upstream writes exceeded") == true })
    }

    @Test
    fun `registry refuses new live connections beyond the open limit`() {
        val registry = ConnectionRegistry(maxOpenConnections = 2)
        val a = registry.tryOpenConnection("l", Protocol.TCP, "c", "u")!!
        assertNotNull(registry.tryOpenConnection("l", Protocol.TCP, "c", "u"))
        assertNull(registry.tryOpenConnection("l", Protocol.TCP, "c", "u"))
        registry.closeConnection(a)
        registry.closeConnection(a) // double close must not free two slots
        assertEquals(1, registry.openConnectionCount())
        assertNotNull(registry.tryOpenConnection("l", Protocol.TCP, "c", "u"))
        assertNull(registry.tryOpenConnection("l", Protocol.TCP, "c", "u"))
    }

    @Test
    fun `TCP listener closes clients beyond the open-connection limit`() {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry(maxOpenConnections = 1)
        TcpEchoServer().use { echo ->
            val listener = TcpListener(ListenerConfig("lim", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port), registry, boss, worker)
            try {
                val port = (listener.start().sync().channel().localAddress() as InetSocketAddress).port
                Socket("127.0.0.1", port).use { first ->
                    waitUntil { registry.openConnectionCount() == 1 }
                    Socket("127.0.0.1", port).use { second ->
                        second.soTimeout = 5000
                        assertEquals(-1, second.getInputStream().read())
                    }
                    first.getOutputStream().write("ok".toByteArray()); first.getOutputStream().flush()
                    val buf = ByteArray(2); var t = 0
                    while (t < 2) { val r = first.getInputStream().read(buf, t, 2 - t); if (r < 0) break; t += r }
                    assertEquals("ok", String(buf))
                }
            } finally {
                listener.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
            }
        }
    }
}
