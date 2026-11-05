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

    // Protobuf payload: field 1 varint 5 (08 05), field 2 len str:"hi" (12 02 68 69)
    private val pbPayload = byteArrayOf(0x08, 0x05, 0x12, 0x02, 0x68, 0x69)
    // Unmasked binary frame (FIN+binary 0x82, len6 0x06) carrying that protobuf payload
    private val pbBinaryFrame = byteArrayOf(0x82.toByte(), 0x06) + pbPayload

    @Test
    fun `decodes a protobuf payload inside a binary frame`() {
        val out = d.render(wsMsg(pbBinaryFrame))
        assertTrue(out.contains("protobuf"), out)
        assertTrue(out.contains("1 varint 5"), out)
        assertTrue(out.contains("2 len str:hi"), out)
    }

    @Test
    fun `round-trips a decoded binary protobuf frame`() {
        assertArrayEquals(pbBinaryFrame, d.parseEdit(d.render(wsMsg(pbBinaryFrame)), wsMsg(pbBinaryFrame)))
    }

    @Test
    fun `editing an inner protobuf field re-encodes and re-frames`() {
        val edited = d.render(wsMsg(pbBinaryFrame)).replace("1 varint 5", "1 varint 9")
        val out = d.parseEdit(edited, wsMsg(pbBinaryFrame))
        assertArrayEquals(byteArrayOf(0x82.toByte(), 0x06, 0x08, 0x09, 0x12, 0x02, 0x68, 0x69), out)
    }

    @Test
    fun `re-masks a decoded binary protobuf frame on edit`() {
        val masked = byteArrayOf(0x82.toByte(), (0x80 or 6).toByte()) + key +
            pbPayload.mapIndexed { i, b -> (b.toInt() xor key[i % 4].toInt()).toByte() }.toByteArray()
        assertArrayEquals(masked, d.parseEdit(d.render(wsMsg(masked)), wsMsg(masked)))
    }

    @Test
    fun `a non-protobuf binary frame still falls back to raw hex`() {
        val f = byteArrayOf(0x82.toByte(), 0x01, 0x00) // payload 0x00 — invalid protobuf (field 0)
        val out = d.render(wsMsg(f))
        assertTrue(out.contains("raw: hex:"), out)
        assertArrayEquals(f, d.parseEdit(out, wsMsg(f)))
    }
}
