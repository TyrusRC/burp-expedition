package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun message(bytes: ByteArray) =
    ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class DissectorRegistryTest {

    @Test
    fun `hex dissector round-trips bytes through render and parseEdit`() {
        val dissector = HexStringDissector()
        val original = message(byteArrayOf(0x48, 0x65, 0x6c, 0x6c, 0x6f))

        val rendered = dissector.render(original)
        val parsed = dissector.parseEdit(rendered, original)

        assertArrayEquals(original.rawBytes, parsed)
    }

    @Test
    fun `parseEdit reflects edited hex text`() {
        val dissector = HexStringDissector()
        val original = message(byteArrayOf(0x00))

        val parsed = dissector.parseEdit("48 65 6c 6c 6f", original)

        assertArrayEquals(byteArrayOf(0x48, 0x65, 0x6c, 0x6c, 0x6f), parsed)
    }

    @Test
    fun `registry falls back to default when no dissector supports the message`() {
        val registry = DissectorRegistry()

        val dissector = registry.dissectorFor(message(byteArrayOf(1, 2, 3)))

        assertTrue(dissector is HexStringDissector)
    }

    @Test
    fun `falls back to default when a dissector throws in supports`() {
        val registry = DissectorRegistry()
        registry.register(object : Dissector {
            override fun supports(message: ProxyMessage): Boolean = throw RuntimeException("boom")
            override fun render(message: ProxyMessage) = "X"
            override fun parseEdit(edited: String, original: ProxyMessage) = original.rawBytes
        })
        assertTrue(registry.dissectorFor(message(byteArrayOf(1, 2, 3))) is HexStringDissector)
    }

    @Test
    fun `registry prefers a registered dissector that supports the message`() {
        val registry = DissectorRegistry()
        val custom = object : Dissector {
            override fun supports(message: ProxyMessage) = message.rawBytes.isNotEmpty() && message.rawBytes[0] == 0xFF.toByte()
            override fun render(message: ProxyMessage) = "CUSTOM"
            override fun parseEdit(edited: String, original: ProxyMessage) = original.rawBytes
        }
        registry.register(custom)

        val matched = registry.dissectorFor(message(byteArrayOf(0xFF.toByte(), 1)))
        val unmatched = registry.dissectorFor(message(byteArrayOf(1, 2)))

        assertSame(custom, matched)
        assertTrue(unmatched is HexStringDissector)
    }
}
