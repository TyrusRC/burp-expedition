package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun quicMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class QuicDissectorTest {

    private val d = QuicDissector()

    // Minimal QUIC v1 Initial Long Header with 8-byte DCID, 0-byte SCID, no token, 0 payload
    // First byte: 0xC0 (long header, fixed bit, Initial type=0x00)
    // Version: 0x00000001 (QUIC v1)
    private val quicInitial: ByteArray = run {
        val out = mutableListOf<Byte>()
        out.add(0xC0.toByte())          // long header, fixed bit, Initial (type=0)
        // version = 0x00000001
        out.add(0x00); out.add(0x00); out.add(0x00); out.add(0x01)
        // DCID length = 8
        out.add(0x08)
        // DCID = 8 bytes
        out.addAll(listOf<Byte>(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08))
        // SCID length = 0
        out.add(0x00)
        // Token length = 0 (varint: single byte 0x00)
        out.add(0x00)
        // Payload length = 0 (varint: single byte 0x00)
        out.add(0x00)
        out.toByteArray()
    }

    @Test
    fun `supports a QUIC v1 Initial packet`() {
        assertTrue(d.supports(quicMsg(quicInitial)))
    }

    @Test
    fun `renders Initial with version and DCID`() {
        val out = d.render(quicMsg(quicInitial))
        assertTrue(out.contains("QUIC"), out)
        assertTrue(out.contains("Initial"), out)
        assertTrue(out.contains("v1"), out)
        assertTrue(out.contains("0102030405060708"), "expected DCID in: $out")
    }

    @Test
    fun `rejects non-QUIC data`() {
        assertFalse(d.supports(quicMsg(byteArrayOf(1, 2, 3))))
        assertFalse(d.supports(quicMsg(byteArrayOf())))
        // Redis RESP (starts with 0x2A which has bit 6=0, bit 7=0 → rejected)
        assertFalse(d.supports(quicMsg("*1\r\n\$4\r\nPING\r\n".toByteArray())))
        // STUN (starts with 0x01 which has bits 7,6 = 0,0 → rejected)
        assertFalse(d.supports(quicMsg(byteArrayOf(0x01, 0x01, 0x00, 0x00))))
    }

    @Test
    fun `rejects short header without fixed bit`() {
        // bit 7=0, bit 6=0 → neither long nor valid short header
        assertFalse(d.supports(quicMsg(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05))))
    }

    @Test
    fun `supports Short Header (1-RTT) with fixed bit`() {
        // bit 7=0, bit 6=1 → short header
        val shortHeader = byteArrayOf(0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09)
        assertTrue(d.supports(quicMsg(shortHeader)))
        val out = d.render(quicMsg(shortHeader))
        assertTrue(out.contains("Short Header"), out)
    }

    @Test
    fun `round-trips through render and parseEdit`() {
        val original = quicMsg(quicInitial)
        val rendered = d.render(original)
        val rebuilt = d.parseEdit(rendered, original)
        assertArrayEquals(quicInitial, rebuilt, "round-trip failed")
    }
}
