package expedition.ui

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class UpstreamAddressParserTest {

    @Test
    fun `parses a host and port`() {
        val (host, port) = UpstreamAddressParser.parse("example.test:8080")
        assertEquals("example.test", host)
        assertEquals(8080, port)
    }

    @Test
    fun `parses an IPv4 address and port`() {
        val (host, port) = UpstreamAddressParser.parse("127.0.0.1:443")
        assertEquals("127.0.0.1", host)
        assertEquals(443, port)
    }

    @Test
    fun `rejects an address with no port`() {
        assertThrows(IllegalArgumentException::class.java) { UpstreamAddressParser.parse("example.test") }
    }

    @Test
    fun `rejects an address with a non-numeric port`() {
        assertThrows(IllegalStateException::class.java) { UpstreamAddressParser.parse("example.test:abc") }
    }
}
