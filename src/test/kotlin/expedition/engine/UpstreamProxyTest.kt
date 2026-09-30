package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.Socket

class UpstreamProxyTest {

    @Test
    fun `relays through an upstream SOCKS5 proxy to the destination`() {
        val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
        TcpEchoServer().use { echo ->
            // Our own SOCKS5 listener acts as the outbound proxy the upstream is chained through.
            val socks = Socks5Listener(Socks5ListenerConfig("out-proxy", "127.0.0.1", 0), registry, boss, worker, gate)
            val socksPort = (socks.start().sync().channel().localAddress() as InetSocketAddress).port

            val config = ListenerConfig(
                "chained", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port,
                upstreamProxy = UpstreamProxy("127.0.0.1", socksPort)
            )
            val listener = TcpListener(config, registry, boss, worker, gate)
            try {
                val port = (listener.start().sync().channel().localAddress() as InetSocketAddress).port
                Socket("127.0.0.1", port).use { client ->
                    client.getOutputStream().write("ping".toByteArray()); client.getOutputStream().flush()
                    val buf = ByteArray(4); var total = 0
                    while (total < 4) { val r = client.getInputStream().read(buf, total, 4 - total); if (r < 0) break; total += r }
                    assertEquals("ping", String(buf))
                }
            } finally {
                listener.stop(); socks.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
            }
        }
    }
}
