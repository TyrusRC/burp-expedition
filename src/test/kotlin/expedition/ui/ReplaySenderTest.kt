package expedition.ui

import expedition.engine.TcpEchoServer
import expedition.engine.UdpEchoServer
import expedition.registry.Protocol
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.ServerSocket

class ReplaySenderTest {

    // I3: replaying a connection whose TCP upstream is down must not throw
    // (uncaught on the EDT) or hang past the timeout — it returns an empty response.
    @Test
    fun `returns empty when the tcp upstream refuses the connection`() {
        val deadPort = ServerSocket(0).use { it.localPort }
        val response = ReplaySender().replay(Protocol.TCP, "127.0.0.1", deadPort, "x".toByteArray(), timeoutMillis = 500)
        assertEquals(0, response.size)
    }

    @Test
    fun `replays bytes over TCP and returns the response`() {
        TcpEchoServer().use { echo ->
            val response = ReplaySender().replay(Protocol.TCP, "127.0.0.1", echo.port, "ping".toByteArray())
            assertArrayEquals("ping".toByteArray(), response)
        }
    }

    @Test
    fun `replays bytes over UDP and returns the response`() {
        UdpEchoServer().use { echo ->
            val response = ReplaySender().replay(Protocol.UDP, "127.0.0.1", echo.port, "ping".toByteArray())
            assertArrayEquals("ping".toByteArray(), response)
        }
    }
}
