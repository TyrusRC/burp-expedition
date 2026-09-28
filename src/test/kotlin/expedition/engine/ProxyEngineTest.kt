package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.ServerSocket

class ProxyEngineTest {

    private fun newEngine(
        registry: ConnectionRegistry = ConnectionRegistry(),
        onError: (String, String) -> Unit = { _, _ -> }
    ) = ProxyEngine(
        registry, InterceptController(), MatchReplaceEngine(),
        certificateProviderSupplier = { null },
        onHeldMessage = { _, _, _, _ -> },
        onError = onError
    )

    @Test
    fun `starts a TCP and a UDP listener and relays through both`() {
        val engine = newEngine()
        TcpEchoServer().use { tcpEcho ->
            UdpEchoServer().use { udpEcho ->
                engine.startListener(ListenerConfig("tcp-a", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", tcpEcho.port))
                engine.startListener(ListenerConfig("udp-a", Protocol.UDP, "127.0.0.1", 0, "127.0.0.1", udpEcho.port))
                assertEquals(setOf("tcp-a", "udp-a"), engine.runningListenerNames())
                engine.shutdown()
            }
        }
    }

    @Test
    fun `rejects a duplicate listener name`() {
        val engine = newEngine()
        TcpEchoServer().use { echo ->
            val config = ListenerConfig("dup", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port)
            engine.startListener(config)
            assertThrows(IllegalArgumentException::class.java) { engine.startListener(config.copy(bindPort = 0)) }
            engine.shutdown()
        }
    }

    @Test
    fun `reports a bind failure through onError instead of crashing`() {
        val errors = mutableListOf<Pair<String, String>>()
        val engine = newEngine(onError = { name, message -> errors.add(name to message) })

        ServerSocket(0).use { reserved ->
            engine.startListener(ListenerConfig("bad-bind", Protocol.TCP, "127.0.0.1", reserved.localPort, "127.0.0.1", 80))
            assertEquals(1, errors.size)
            assertEquals("bad-bind", errors[0].first)
        }

        TcpEchoServer().use { echo ->
            engine.startListener(ListenerConfig("good", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port))
            assertTrue(engine.runningListenerNames().contains("good"))
        }
        engine.shutdown()
    }

    @Test
    fun `shutdown releases bound ports so they can be reused immediately`() {
        val engine = newEngine()
        val fixedPort = ServerSocket(0).use { it.localPort }
        TcpEchoServer().use { echo ->
            engine.startListener(ListenerConfig("release", Protocol.TCP, "127.0.0.1", fixedPort, "127.0.0.1", echo.port))
            engine.shutdown()
        }
        ServerSocket(fixedPort).close()
    }
}
