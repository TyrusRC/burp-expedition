package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun amqpMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class AmqpDissectorTest {

    private val d = AmqpDissector()

    // AMQP 0-9-1 protocol header handshake: "AMQP" + 0x00 0x00 0x09 0x01
    private val protocolHeader = byteArrayOf(
        0x41, 0x4D, 0x51, 0x50, // "AMQP"
        0x00, 0x00, 0x09, 0x01, // 0-9-1
    )

    // METHOD frame carrying connection.Start (class 10, method 10):
    // type=1(METHOD) channel=0 size=4 payload=[class 0x000A, method 0x000A] frame-end=0xCE
    private val connectionStart = byteArrayOf(
        0x01,                               // type: METHOD
        0x00, 0x00,                         // channel: 0
        0x00, 0x00, 0x00, 0x04,             // size: 4
        0x00, 0x0A,                         // class-id: 10 (connection)
        0x00, 0x0A,                         // method-id: 10 (Start)
        0xCE.toByte(),                      // frame-end
    )

    @Test
    fun `supports the AMQP protocol-header handshake`() {
        assertTrue(d.supports(amqpMsg(protocolHeader)))
    }

    @Test
    fun `supports a well-formed METHOD frame ending in 0xCE`() {
        assertTrue(d.supports(amqpMsg(connectionStart)))
    }

    @Test
    fun `rejects non-AMQP data`() {
        assertFalse(d.supports(amqpMsg(byteArrayOf(1, 2, 3, 4, 5))))
        assertFalse(d.supports(amqpMsg(byteArrayOf())))
    }

    @Test
    fun `rejects a frame without the 0xCE terminator`() {
        val bad = connectionStart.copyOf()
        bad[bad.size - 1] = 0x00 // corrupt frame-end marker
        assertFalse(d.supports(amqpMsg(bad)))
    }

    @Test
    fun `renders a connection Start method frame`() {
        val out = d.render(amqpMsg(connectionStart))
        assertTrue(out.contains("connection"), out)
        assertTrue(out.contains("Start"), out)
    }

    @Test
    fun `round-trips through render and parseEdit`() {
        val original = amqpMsg(connectionStart)
        val rendered = d.render(original)
        val rebuilt = d.parseEdit(rendered, original)
        assertArrayEquals(connectionStart, rebuilt, "round-trip failed")
    }
}
