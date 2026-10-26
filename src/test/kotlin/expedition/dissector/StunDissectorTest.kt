package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun stunMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class StunDissectorTest {

    private val d = StunDissector()

    // STUN Binding Success Response with XOR-MAPPED-ADDRESS
    // type=0x0101 (Binding Success), length=12, magic=0x2112A442, txn=12 bytes
    // attr: XOR-MAPPED-ADDRESS (0x0020), len=8, family=IPv4, port^magic, ip^magic
    private val bindingResponse = byteArrayOf(
        0x01, 0x01,             // type: Binding Success
        0x00, 0x0C,             // length: 12 (one attribute: 4 header + 8 value)
        0x21, 0x12, 0xA4.toByte(), 0x42, // magic cookie
        // transaction ID: 12 bytes
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        // XOR-MAPPED-ADDRESS attribute
        0x00, 0x20,             // attr type
        0x00, 0x08,             // attr length: 8
        0x00, 0x01,             // reserved=0, family=IPv4
        // port XOR (magic >> 16): 8080=0x1F90, 0x1F90 ^ 0x2112 = 0x3E82
        0x3E, 0x82.toByte(),
        // IP XOR magic: 192.168.1.1 = C0.A8.01.01, magic = 21.12.A4.42
        // C0^21=E1, A8^12=BA, 01^A4=A5, 01^42=43
        0xE1.toByte(), 0xBA.toByte(), 0xA5.toByte(), 0x43,
    )

    @Test
    fun `supports a valid STUN Binding Response`() {
        assertTrue(d.supports(stunMsg(bindingResponse)))
    }

    @Test
    fun `rejects non-STUN data`() {
        assertFalse(d.supports(stunMsg(byteArrayOf(1, 2, 3, 4, 5))))
        assertFalse(d.supports(stunMsg(byteArrayOf())))
        // Redis RESP
        assertFalse(d.supports(stunMsg("+PONG\r\n".toByteArray())))
        // HTTP
        assertFalse(d.supports(stunMsg("HTTP/1.1 200 OK\r\n".toByteArray())))
    }

    @Test
    fun `rejects packets with wrong magic cookie`() {
        val bad = bindingResponse.copyOf()
        bad[4] = 0x00 // corrupt magic cookie
        assertFalse(d.supports(stunMsg(bad)))
    }

    @Test
    fun `renders Binding Success with decoded XOR-MAPPED-ADDRESS`() {
        val out = d.render(stunMsg(bindingResponse))
        assertTrue(out.contains("STUN"), out)
        assertTrue(out.contains("Binding"), out)
        assertTrue(out.contains("Success"), out)
        assertTrue(out.contains("XOR-MAPPED-ADDRESS"), out)
        assertTrue(out.contains("192.168.1.1"), "expected decoded IP in: $out")
        assertTrue(out.contains("8080"), "expected decoded port in: $out")
    }

    @Test
    fun `round-trips through render and parseEdit`() {
        val original = stunMsg(bindingResponse)
        val rendered = d.render(original)
        val rebuilt = d.parseEdit(rendered, original)
        assertArrayEquals(bindingResponse, rebuilt, "round-trip failed")
    }
}
