package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant

class GrpcDissectorTest {

    private val d = GrpcDissector()
    private fun msg(b: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), b)

    // protobuf: field 1 varint 5 (08 05), field 2 len str:"hi" (12 02 68 69) — 6 bytes
    private val pb = byteArrayOf(0x08, 0x05, 0x12, 0x02, 0x68, 0x69)
    private fun lenBE(n: Int) = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())
    // one uncompressed gRPC message: flag 0x00 + len + protobuf
    private val oneMsg = byteArrayOf(0x00) + lenBE(pb.size) + pb

    @Test fun `supports a single uncompressed gRPC message`() {
        assertTrue(d.supports(msg(oneMsg)))
    }

    @Test fun `rejects a frame whose declared length does not tile the buffer`() {
        assertFalse(d.supports(msg(byteArrayOf(0x00) + lenBE(99) + pb)))
    }

    @Test fun `rejects a frame whose uncompressed payload is not protobuf`() {
        // payload 0x00 => protobuf field number 0 => invalid
        assertFalse(d.supports(msg(byteArrayOf(0x00) + lenBE(1) + byteArrayOf(0x00))))
    }

    @Test fun `decodes the protobuf payload of an uncompressed message`() {
        val out = d.render(msg(oneMsg))
        assertTrue(out.contains("#grpc 0 u"), out)
        assertTrue(out.contains("1 varint 5"), out)
        assertTrue(out.contains("2 len str:hi"), out)
    }

    @Test fun `round-trips a single uncompressed message`() {
        assertArrayEquals(oneMsg, d.parseEdit(d.render(msg(oneMsg)), msg(oneMsg)))
    }

    @Test fun `editing an inner field re-encodes and recomputes the length prefix`() {
        val edited = d.render(msg(oneMsg)).replace("1 varint 5", "1 varint 9")
        val expected = byteArrayOf(0x00) + lenBE(pb.size) + byteArrayOf(0x08, 0x09, 0x12, 0x02, 0x68, 0x69)
        assertArrayEquals(expected, d.parseEdit(edited, msg(oneMsg)))
    }

    @Test fun `handles several concatenated messages and round-trips them`() {
        val two = oneMsg + oneMsg
        assertTrue(d.supports(msg(two)))
        val out = d.render(msg(two))
        assertTrue(out.contains("#grpc 0 u") && out.contains("#grpc 1 u"), out)
        assertArrayEquals(two, d.parseEdit(out, msg(two)))
    }

    @Test fun `shows a compressed message as hex and round-trips it`() {
        val compressed = byteArrayOf(0x01) + lenBE(3) + byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        val buf = oneMsg + compressed   // one protobuf frame (so it's recognised as gRPC) + one compressed
        val out = d.render(msg(buf))
        assertTrue(out.contains("#grpc 1 c hex:aabbcc"), out)
        assertArrayEquals(buf, d.parseEdit(out, msg(buf)))
    }
}
