package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun wsMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class WebSocketDissectorTest {

    private val d = WebSocketDissector()

    // Masked text frame: FIN+text(0x81), MASK+len5(0x85), key, "Hello" XOR key
    private val key = byteArrayOf(0x37, 0xfa.toByte(), 0x21, 0x3d)
    private val maskedHello = "Hello".toByteArray().mapIndexed { i, b -> (b.toInt() xor key[i % 4].toInt()).toByte() }.toByteArray()
    private val textFrame = byteArrayOf(0x81.toByte(), 0x85.toByte()) + key + maskedHello

    @Test
    fun `renders a masked text frame with the unmasked text`() {
        val out = d.render(wsMsg(textFrame))
        assertTrue(out.contains("WS text"), out)
        assertTrue(out.contains("Hello"), out)
    }

    @Test
    fun `round-trips a masked text frame`() {
        assertArrayEquals(textFrame, d.parseEdit(d.render(wsMsg(textFrame)), wsMsg(textFrame)))
    }

    @Test
    fun `editing the text re-masks and recomputes length`() {
        val out = d.parseEdit("WS text: Hi", wsMsg(textFrame))
        val expected = byteArrayOf(0x81.toByte(), 0x82.toByte()) + key +
            "Hi".toByteArray().mapIndexed { i, b -> (b.toInt() xor key[i % 4].toInt()).toByte() }.toByteArray()
        assertArrayEquals(expected, out)
    }

    @Test
    fun `renders and round-trips a control frame via raw hex`() {
        val ping = byteArrayOf(0x89.toByte(), 0x00) // ping, no payload
        val out = d.render(wsMsg(ping))
        assertTrue(out.contains("WS ping"), out)
        assertArrayEquals(ping, d.parseEdit(out, wsMsg(ping)))
    }

    @Test
    fun `parse rejects an overflowing length instead of throwing`() {
        // opcode 2, unmasked, 8-byte length = 0x7FFFFFFF; pos+len overflows Int — must reject, not crash.
        val f = byteArrayOf(0x82.toByte(), 0x7F, 0, 0, 0, 0, 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        assertFalse(d.supports(wsMsg(f)))
    }

    @Test
    fun `supports a valid frame and rejects non-frames`() {
        assertTrue(d.supports(wsMsg(textFrame)))
        assertFalse(d.supports(wsMsg(byteArrayOf())))
        // opcode 5 is reserved/invalid
        assertFalse(d.supports(wsMsg(byteArrayOf(0x85.toByte(), 0x00))))
    }
}
