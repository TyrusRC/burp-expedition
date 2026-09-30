package expedition.fuzz

import expedition.engine.TcpEchoServer
import expedition.engine.UdpEchoServer
import expedition.registry.Protocol
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import kotlin.random.Random

class FuzzerTest {

    @Test
    fun `fuzzes a TCP target and returns one case per iteration`() {
        TcpEchoServer().use { echo ->
            val cases = Fuzzer().fuzz(
                Protocol.TCP, "127.0.0.1", echo.port, "ping".toByteArray(), iterations = 5, mutator = ByteMutator(Random(1))
            )
            assertEquals(5, cases.size)
            // The echo server returns each mutated input unchanged.
            cases.forEach { assertArrayEquals(it.input, it.response) }
        }
    }

    @Test
    fun `fuzzes a UDP target`() {
        UdpEchoServer().use { echo ->
            val cases = Fuzzer().fuzz(
                Protocol.UDP, "127.0.0.1", echo.port, "ping".toByteArray(), iterations = 3, mutator = ByteMutator(Random(2))
            )
            assertEquals(3, cases.size)
        }
    }
}
