package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun dnp3Msg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class Dnp3DissectorTest {

    private val d = Dnp3Dissector()

    // start 0x0564, len=5, ctrl=0xC4, dst=4 (LE), src=1 (LE), crc (dummy)
    private val frame = byteArrayOf(0x05, 0x64, 0x05, 0xC4.toByte(), 0x04, 0x00, 0x01, 0x00, 0xAA.toByte(), 0xBB.toByte())

    @Test
    fun `renders the data-link header`() {
        val out = d.render(dnp3Msg(frame))
        assertTrue(out.contains("DNP3"), out)
        assertTrue(out.contains("dst=4"), out)
        assertTrue(out.contains("src=1"), out)
    }

    @Test
    fun `round-trips via raw hex`() {
        assertArrayEquals(frame, d.parseEdit(d.render(dnp3Msg(frame)), dnp3Msg(frame)))
    }

    @Test
    fun `supports a DNP3 frame and rejects others`() {
        assertTrue(d.supports(dnp3Msg(frame)))
        assertFalse(d.supports(dnp3Msg(byteArrayOf())))
        assertFalse(d.supports(dnp3Msg(byteArrayOf(0x05, 0x64, 0x05)))) // too short
        assertFalse(d.supports(dnp3Msg(byteArrayOf(0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0)))) // wrong start
    }
}
