package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun h2msg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class Http2FrameDissectorTest {

    private val d = Http2FrameDissector()

    // A minimal SETTINGS frame: type=4, length=6 (one setting), flags=0, stream=0
    // Setting: HEADER_TABLE_SIZE (id=1) = 4096
    private val settingsFrame = byteArrayOf(
        0x00, 0x00, 0x06, // length=6
        0x04,             // type=SETTINGS
        0x00,             // flags
        0x00, 0x00, 0x00, 0x00, // stream=0
        // payload: setting id=1 (HEADER_TABLE_SIZE), value=4096
        0x00, 0x01,
        0x00, 0x00, 0x10, 0x00,
    )

    // A DATA frame with a simple gRPC payload (compressed=0, len=2, protobuf=0802)
    private val dataFrame = byteArrayOf(
        0x00, 0x00, 0x07, // length=7
        0x00,             // type=DATA
        0x01,             // flags=END_STREAM
        0x00, 0x00, 0x00, 0x01, // stream=1
        // gRPC framing: compressed=0, msg_len=2
        0x00,
        0x00, 0x00, 0x00, 0x02,
        // protobuf: field 1, varint, value 42
        0x08, 0x2A,
    )

    @Test
    fun `supports a valid HTTP2 SETTINGS frame`() {
        assertTrue(d.supports(h2msg(settingsFrame)))
    }

    @Test
    fun `supports a valid HTTP2 DATA frame`() {
        assertTrue(d.supports(h2msg(dataFrame)))
    }

    @Test
    fun `supports HTTP2 connection preface`() {
        val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.ISO_8859_1) + settingsFrame
        assertTrue(d.supports(h2msg(preface)))
    }

    @Test
    fun `rejects Redis RESP`() {
        val resp = "*1\r\n\$4\r\nPING\r\n".toByteArray(Charsets.ISO_8859_1)
        assertFalse(d.supports(h2msg(resp)))
    }

    @Test
    fun `rejects random binary`() {
        assertFalse(d.supports(h2msg(byteArrayOf(0x42, 0x43, 0x44))))
        assertFalse(d.supports(h2msg(byteArrayOf())))
    }

    @Test
    fun `rejects frame where type byte exceeds 9`() {
        val bad = settingsFrame.copyOf()
        bad[3] = 0x0A // type=10, invalid
        assertFalse(d.supports(h2msg(bad)))
    }

    @Test
    fun `renders SETTINGS with decoded values`() {
        val out = d.render(h2msg(settingsFrame))
        assertTrue(out.contains("SETTINGS"), out)
        assertTrue(out.contains("HEADER_TABLE_SIZE"), out)
        assertTrue(out.contains("4096"), out)
    }

    @Test
    fun `renders DATA with gRPC protobuf decode`() {
        val out = d.render(h2msg(dataFrame))
        assertTrue(out.contains("DATA"), out)
        assertTrue(out.contains("END_STREAM"), out)
        assertTrue(out.contains("grpc:"), out)
    }

    @Test
    fun `round-trips DATA frame through render and parseEdit`() {
        val original = h2msg(dataFrame)
        val rendered = d.render(original)
        val rebuilt = d.parseEdit(rendered, original)
        assertArrayEquals(dataFrame, rebuilt, "round-trip failed:\nrendered:\n$rendered")
    }

    @Test
    fun `SETTINGS frame renders decoded values but is not round-trippable`() {
        val original = h2msg(settingsFrame)
        val rendered = d.render(original)
        // SETTINGS renders as decoded key=value, not hex — parseEdit produces
        // an empty-payload frame (settings edit is not supported). Verify the
        // render content is correct, not the round-trip.
        assertTrue(rendered.contains("SETTINGS"), rendered)
        assertTrue(rendered.contains("HEADER_TABLE_SIZE = 4096"), rendered)
    }
}
