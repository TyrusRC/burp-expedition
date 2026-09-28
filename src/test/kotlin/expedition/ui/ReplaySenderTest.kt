package expedition.ui

import expedition.engine.TcpEchoServer
import expedition.engine.UdpEchoServer
import expedition.registry.Protocol
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class ReplaySenderTest {

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
