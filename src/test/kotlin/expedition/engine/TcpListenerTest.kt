package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.pipeline.MessageGate
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import io.netty.channel.nio.NioEventLoopGroup
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.Socket
import java.time.Duration
import java.time.Instant

class TcpListenerTest {

    private fun startedPort(listener: TcpListener) =
        (listener.start().sync().channel().localAddress() as java.net.InetSocketAddress).port

    @Test
    fun `relays bytes between client and upstream and records them in the registry`() {
        val boss = NioEventLoopGroup(1)
        val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        TcpEchoServer().use { echo ->
            val config = ListenerConfig("t1", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port)
            val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
            val listener = TcpListener(config, registry, boss, worker, gate)
            try {
                val port = startedPort(listener)
                Socket("127.0.0.1", port).use { client ->
                    client.getOutputStream().write("ping".toByteArray())
                    client.getOutputStream().flush()
                    val buffer = ByteArray(4)
                    var total = 0
                    while (total < 4) {
                        val read = client.getInputStream().read(buffer, total, 4 - total)
                        if (read < 0) break
                        total += read
                    }
                    assertEquals("ping", String(buffer))
                }
                waitUntil { registry.allMessages().size >= 2 }
                val messages = registry.allMessages()
                assertTrue(messages.any { it.direction == Direction.CLIENT_TO_UPSTREAM })
                assertTrue(messages.any { it.direction == Direction.UPSTREAM_TO_CLIENT })
            } finally {
                listener.stop()
            }
        }
        boss.shutdownGracefully().sync()
        worker.shutdownGracefully().sync()
    }

    @Test
    fun `closes the client connection cleanly when the upstream refuses the connection`() {
        val boss = NioEventLoopGroup(1)
        val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val deadPort = java.net.ServerSocket(0).use { it.localPort }
        val config = ListenerConfig("t2", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", deadPort)
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
        val listener = TcpListener(config, registry, boss, worker, gate)
        try {
            val port = startedPort(listener)
            Socket("127.0.0.1", port).use { client ->
                client.getOutputStream().write("hi".toByteArray())
                client.getOutputStream().flush()
                assertEquals(-1, client.getInputStream().read(), "client stream should be closed, not hung")
            }
            waitUntil { registry.allConnections().any { it.closedAt != null } }
        } finally {
            listener.stop()
            boss.shutdownGracefully().sync()
            worker.shutdownGracefully().sync()
        }
    }

    @Test
    fun `holds a message until forward is called, then delivers the edited bytes upstream`() {
        val boss = NioEventLoopGroup(1)
        val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val intercept = InterceptController().apply { setEnabled(true) }
        var heldId = -1L
        TcpEchoServer().use { echo ->
            val config = ListenerConfig("t3", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port)
            val gate = MessageGate(registry, intercept, MatchReplaceEngine()) { id, _, _, _ -> heldId = id }
            val listener = TcpListener(config, registry, boss, worker, gate)
            try {
                val port = startedPort(listener)
                Socket("127.0.0.1", port).use { client ->
                    client.getOutputStream().write("orig".toByteArray())
                    client.getOutputStream().flush()
                    waitUntil { heldId != -1L }
                    intercept.forward(heldId, "edit".toByteArray())
                    // The echoed response also passes through the gate; disable intercept
                    // now so it isn't held too (this test only exercises one direction).
                    intercept.setEnabled(false)
                    val buffer = ByteArray(4)
                    var total = 0
                    while (total < 4) {
                        val read = client.getInputStream().read(buffer, total, 4 - total)
                        if (read < 0) break
                        total += read
                    }
                    assertEquals("edit", String(buffer))
                }
            } finally {
                listener.stop()
                boss.shutdownGracefully().sync()
                worker.shutdownGracefully().sync()
            }
        }
    }

    @Test
    fun `applies match and replace rules even when intercept is disabled`() {
        val boss = NioEventLoopGroup(1)
        val worker = NioEventLoopGroup()
        val registry = ConnectionRegistry()
        val matchReplace = MatchReplaceEngine().apply { addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar")) }
        TcpEchoServer().use { echo ->
            val config = ListenerConfig("t4", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port)
            val gate = MessageGate(registry, InterceptController(), matchReplace) { _, _, _, _ -> }
            val listener = TcpListener(config, registry, boss, worker, gate)
            try {
                val port = startedPort(listener)
                Socket("127.0.0.1", port).use { client ->
                    client.getOutputStream().write("foo".toByteArray())
                    client.getOutputStream().flush()
                    val buffer = ByteArray(3)
                    var total = 0
                    while (total < 3) {
                        val read = client.getInputStream().read(buffer, total, 3 - total)
                        if (read < 0) break
                        total += read
                    }
                    assertEquals("bar", String(buffer))
                }
            } finally {
                listener.stop()
                boss.shutdownGracefully().sync()
                worker.shutdownGracefully().sync()
            }
        }
    }
}

fun waitUntil(timeout: Duration = Duration.ofSeconds(5), condition: () -> Boolean) {
    val deadline = Instant.now().plus(timeout)
    while (!condition()) {
        if (Instant.now().isAfter(deadline)) org.junit.jupiter.api.Assertions.fail<Unit>("condition not met within $timeout")
        Thread.sleep(20)
    }
}
