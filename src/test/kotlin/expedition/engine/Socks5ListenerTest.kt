package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket

class Socks5ListenerTest {

    private fun startedPort(l: Socks5Listener) =
        (l.start().sync().channel().localAddress() as InetSocketAddress).port

    private fun readN(socket: Socket, n: Int): ByteArray {
        val buf = ByteArray(n); var total = 0
        while (total < n) {
            val r = socket.getInputStream().read(buf, total, n - total)
            if (r < 0) break; total += r
        }
        return buf
    }

    @Test
    fun `relays through SOCKS5 to the negotiated destination and records it`() {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        TcpEchoServer().use { echo ->
            val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
            val listener = Socks5Listener(Socks5ListenerConfig("socks", "127.0.0.1", 0), registry, boss, worker, gate)
            try {
                val port = startedPort(listener)
                val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
                Socket(proxy).use { client ->
                    client.connect(InetSocketAddress("127.0.0.1", echo.port))
                    client.getOutputStream().write("ping".toByteArray()); client.getOutputStream().flush()
                    assertEquals("ping", String(readN(client, 4)))
                }
                waitUntil { registry.allMessages().size >= 2 }
                assertTrue(registry.allMessages().any { it.direction == Direction.CLIENT_TO_UPSTREAM })
                assertTrue(registry.allMessages().any { it.direction == Direction.UPSTREAM_TO_CLIENT })
            } finally {
                listener.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
            }
        }
    }

    @Test
    fun `applies match and replace on the SOCKS5 relay`() {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val mr = MatchReplaceEngine().apply { addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar")) }
        TcpEchoServer().use { echo ->
            val gate = MessageGate(registry, InterceptController(), mr) { _, _, _, _ -> }
            val listener = Socks5Listener(Socks5ListenerConfig("socks2", "127.0.0.1", 0), registry, boss, worker, gate)
            try {
                val port = startedPort(listener)
                val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
                Socket(proxy).use { client ->
                    client.connect(InetSocketAddress("127.0.0.1", echo.port))
                    client.getOutputStream().write("foo".toByteArray()); client.getOutputStream().flush()
                    assertEquals("bar", String(readN(client, 3)))
                }
            } finally {
                listener.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
            }
        }
    }
}
