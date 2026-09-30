package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun msg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class ProtobufDissectorTest {

    private val d = ProtobufDissector()

    @Test
    fun `renders a varint field`() {
        // field 1, wire type 0 (varint), value 150 -> 08 96 01
        val rendered = d.render(msg(byteArrayOf(0x08, 0x96.toByte(), 0x01)))
        assertEquals("1 varint 150", rendered.trim())
    }

    @Test
    fun `renders a length-delimited string field`() {
        // field 2, wire type 2 (len), "testing"
        val bytes = byteArrayOf(0x12, 0x07) + "testing".toByteArray()
        assertEquals("2 len str:testing", d.render(msg(bytes)).trim())
    }

    @Test
    fun `round-trips varint, len, i32 and i64 fields through render and parseEdit`() {
        val bytes = byteArrayOf(0x08, 0x96.toByte(), 0x01) +                       // f1 varint 150
            (byteArrayOf(0x12, 0x07) + "testing".toByteArray()) +                  // f2 len "testing"
            byteArrayOf(0x2D, 0xEF.toByte(), 0xBE.toByte(), 0xAD.toByte(), 0xDE.toByte()) + // f5 i32
            byteArrayOf(0x31, 1, 2, 3, 4, 5, 6, 7, 8)                              // f6 i64
        val original = msg(bytes)
        val roundTripped = d.parseEdit(d.render(original), original)
        assertArrayEquals(bytes, roundTripped)
    }

    @Test
    fun `parseEdit encodes hand-written text`() {
        val out = d.parseEdit("1 varint 150", msg(byteArrayOf()))
        assertArrayEquals(byteArrayOf(0x08, 0x96.toByte(), 0x01), out)
    }

    @Test
    fun `renders non-printable length-delimited bytes as hex`() {
        val bytes = byteArrayOf(0x12, 0x03, 0x00, 0x01, 0x02)
        assertEquals("2 len hex:000102", d.render(msg(bytes)).trim())
    }

    @Test
    fun `supports valid protobuf and rejects non-protobuf`() {
        assertTrue(d.supports(msg(byteArrayOf(0x08, 0x96.toByte(), 0x01))))
        // wire type 7 is invalid
        assertFalse(d.supports(msg(byteArrayOf(0x07))))
        // empty is not protobuf
        assertFalse(d.supports(msg(byteArrayOf())))
        // truncated length-delimited (claims 5 bytes, has 1)
        assertFalse(d.supports(msg(byteArrayOf(0x12, 0x05, 0x41))))
    }
}
