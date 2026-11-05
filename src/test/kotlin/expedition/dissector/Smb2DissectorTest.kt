package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun smbMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class Smb2DissectorTest {

    private val d = Smb2Dissector()

    // A hand-built SMB2 NEGOTIATE request header (64 bytes, all fields little-endian).
    // magic 0xFE 'S' 'M' 'B', StructureSize=64, Command=0 (NEGOTIATE), Flags=0 (request),
    // MessageId=42.
    private fun negotiateHeader(): ByteArray {
        val h = ByteArray(64)
        h[0] = 0xFE.toByte(); h[1] = 'S'.code.toByte(); h[2] = 'M'.code.toByte(); h[3] = 'B'.code.toByte()
        h[4] = 64; h[5] = 0                 // StructureSize = 64 (LE)
        h[12] = 0; h[13] = 0                // Command = 0 (NEGOTIATE)
        h[16] = 0; h[17] = 0; h[18] = 0; h[19] = 0 // Flags = 0 (request)
        h[24] = 42                          // MessageId = 42 (LE, low byte)
        return h
    }

    // Same header preceded by a 4-byte NetBIOS session header: 0x00 + 3-byte BE length.
    private fun withNetBios(smb: ByteArray): ByteArray {
        val buf = ByteArray(4 + smb.size)
        buf[0] = 0x00
        buf[1] = ((smb.size ushr 16) and 0xff).toByte()
        buf[2] = ((smb.size ushr 8) and 0xff).toByte()
        buf[3] = (smb.size and 0xff).toByte()
        System.arraycopy(smb, 0, buf, 4, smb.size)
        return buf
    }

    @Test
    fun `supports a bare SMB2 NEGOTIATE request header`() {
        assertTrue(d.supports(smbMsg(negotiateHeader())))
    }

    @Test
    fun `supports an SMB2 header behind a NetBIOS session header`() {
        assertTrue(d.supports(smbMsg(withNetBios(negotiateHeader()))))
    }

    @Test
    fun `rejects non-SMB2 data`() {
        assertFalse(d.supports(smbMsg(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))))
        assertFalse(d.supports(smbMsg(byteArrayOf())))
        assertFalse(d.supports(smbMsg("+PONG\r\n".toByteArray())))
    }

    @Test
    fun `rejects the magic with a wrong StructureSize`() {
        val bad = negotiateHeader()
        bad[4] = 65 // StructureSize != 64
        assertFalse(d.supports(smbMsg(bad)))
    }

    @Test
    fun `renders the NEGOTIATE request`() {
        val out = d.render(smbMsg(negotiateHeader()))
        assertTrue(out.contains("SMB2"), out)
        assertTrue(out.contains("NEGOTIATE"), out)
        assertTrue(out.contains("42"), out)
    }

    @Test
    fun `round-trips a bare header through render and parseEdit`() {
        val original = negotiateHeader()
        val rebuilt = d.parseEdit(d.render(smbMsg(original)), smbMsg(original))
        assertArrayEquals(original, rebuilt, "round-trip failed")
    }

    @Test
    fun `round-trips a NetBIOS-framed header through render and parseEdit`() {
        val original = withNetBios(negotiateHeader())
        val rebuilt = d.parseEdit(d.render(smbMsg(original)), smbMsg(original))
        assertArrayEquals(original, rebuilt, "round-trip failed")
    }
}
