package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun dnsMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class DnsDissectorTest {

    private val d = DnsDissector()

    // Standard query for example.com A/IN, id 0x1234, RD set.
    private val query = byteArrayOf(
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ) + byteArrayOf(0x07) + "example".toByteArray() + byteArrayOf(0x03) + "com".toByteArray() +
        byteArrayOf(0x00, 0x00, 0x01, 0x00, 0x01)

    @Test
    fun `renders the header and question`() {
        val out = d.render(dnsMsg(query))
        assertTrue(out.contains("DNS"), out)
        assertTrue(out.contains("id=0x1234"), out)
        assertTrue(out.contains("example.com"), out)
        assertTrue(out.contains(" A "), "expected A record type in: $out")
    }

    @Test
    fun `round-trips through render and parseEdit`() {
        val original = dnsMsg(query)
        assertArrayEquals(query, d.parseEdit(d.render(original), original))
    }

    @Test
    fun `supports a valid DNS message and rejects non-DNS`() {
        assertTrue(d.supports(dnsMsg(query)))
        assertFalse(d.supports(dnsMsg(byteArrayOf(1, 2, 3))))
        assertFalse(d.supports(dnsMsg(byteArrayOf())))
        // header claims 1 question but no question section follows
        assertFalse(d.supports(dnsMsg(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))))
    }
}
