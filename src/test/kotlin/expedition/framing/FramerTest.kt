package expedition.framing

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteOrder

class FramerTest {

    private fun Framer.feedAll(vararg chunks: ByteArray) = chunks.flatMap { feed(it) }
    private fun List<ByteArray>.strings() = map { String(it, Charsets.ISO_8859_1) }
    private fun s(x: String) = x.toByteArray(Charsets.ISO_8859_1)
    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    // ── Passthrough ────────────────────────────────────────────────────────
    @Test
    fun `passthrough emits each chunk unchanged and buffers nothing`() {
        val f = FramingSpec.Passthrough.newFramer()
        assertEquals(listOf("ab", "c"), f.feedAll(s("ab"), s("c")).strings())
        assertNull(f.flush())
    }

    // ── Delimiter ──────────────────────────────────────────────────────────
    @Test
    fun `delimiter reassembles a message split across many chunks`() {
        val f = FramingSpec.Delimiter(s("\r\n")).newFramer()
        val out = "PING hello\r\n".map { f.feed(s(it.toString())) }.flatten()
        assertEquals(listOf("PING hello\r\n"), out.strings())
    }

    @Test
    fun `delimiter split across chunk boundary is still found`() {
        val f = FramingSpec.Delimiter(s("\r\n")).newFramer()
        assertTrue(f.feed(s("abc\r")).isEmpty())
        assertEquals(listOf("abc\r\n"), f.feed(s("\nde")).strings())
        assertEquals("de", String(f.flush()!!))
    }

    @Test
    fun `delimiter emits several messages from one chunk and keeps the tail`() {
        val f = FramingSpec.Delimiter(s("\n")).newFramer()
        assertEquals(listOf("a\n", "bb\n", "\n"), f.feed(s("a\nbb\n\ncc")).strings())
        assertEquals(listOf("ccd\n"), f.feed(s("d\n")).strings())
        assertNull(f.flush())
    }

    @Test
    fun `delimiter flush returns the remainder once and then nothing`() {
        val f = FramingSpec.Delimiter(s("\n")).newFramer()
        f.feed(s("partial"))
        assertEquals("partial", String(f.flush()!!))
        assertNull(f.flush())
    }

    @Test
    fun `delimiter overflow flushes raw and warns`() {
        val warnings = mutableListOf<String>()
        val f = FramingSpec.Delimiter(s("\n"), maxFrameBytes = 8).newFramer { warnings += it }
        assertTrue(f.feed(s("12345")).isEmpty())
        assertEquals(listOf("123456789"), f.feed(s("6789")).strings())
        assertEquals(1, warnings.size)
        // framing resumes normally afterwards
        assertEquals(listOf("x\n"), f.feed(s("x\n")).strings())
    }

    @Test
    fun `concatenated output always equals the input stream`() {
        val f = FramingSpec.Delimiter(s("\r\n"), maxFrameBytes = 16).newFramer()
        val input = "GET /\r\nHost: x\r\n\r\nthis line is far too long for the cap\r\ntail"
        val out = input.chunked(3).flatMap { f.feed(s(it)) } + listOfNotNull(f.flush())
        assertEquals(input, out.strings().joinToString(""))
    }

    // ── Length prefix ──────────────────────────────────────────────────────
    @Test
    fun `length prefix big endian frames split byte by byte`() {
        val f = FramingSpec.LengthPrefix(lengthFieldSize = 2).newFramer()
        val frame = b(0, 3) + s("abc")
        val out = frame.flatMap { f.feed(byteArrayOf(it)) }
        assertEquals(1, out.size)
        assertArrayEquals(frame, out[0]) // header kept
    }

    @Test
    fun `length prefix emits several frames from one chunk and keeps a partial one`() {
        val f = FramingSpec.LengthPrefix(lengthFieldSize = 1).newFramer()
        val out = f.feed(b(1) + s("a") + b(2) + s("bc") + b(0) + b(3) + s("d"))
        assertEquals(listOf("\u0001a", "\u0002bc", "\u0000"), out.strings())
        assertEquals(listOf("\u0003def"), f.feed(s("ef")).strings())
        assertNull(f.flush())
    }

    @Test
    fun `length prefix honours offset, little endian and adjustment`() {
        // 2-byte type, then 4-byte LE length that counts the whole frame (adjust = -6)
        val spec = FramingSpec.LengthPrefix(lengthFieldOffset = 2, lengthFieldSize = 4,
            byteOrder = ByteOrder.LITTLE_ENDIAN, lengthAdjustment = -6)
        val f = spec.newFramer()
        val frame = b(0x10, 0x20, 9, 0, 0, 0) + s("xyz")
        val out = f.feedAll(frame.copyOfRange(0, 4), frame.copyOfRange(4, 9) + frame)
        assertEquals(2, out.size)
        out.forEach { assertArrayEquals(frame, it) }
    }

    @Test
    fun `length prefix flushes an incomplete frame on close`() {
        val f = FramingSpec.LengthPrefix(lengthFieldSize = 4).newFramer()
        assertTrue(f.feed(b(0, 0, 0, 10) + s("abc")).isEmpty())
        assertArrayEquals(b(0, 0, 0, 10) + s("abc"), f.flush())
        assertNull(f.flush())
    }

    @Test
    fun `length prefix oversize frame passes through unbuffered then resyncs`() {
        val warnings = mutableListOf<String>()
        val f = FramingSpec.LengthPrefix(lengthFieldSize = 1, maxFrameBytes = 4).newFramer { warnings += it }
        val out = f.feedAll(b(6) + s("ab"), s("cd"), s("ef") + b(1) + s("z"))
        assertEquals(listOf("\u0006ab", "cd", "ef", "\u0001z"), out.strings())
        assertEquals(1, warnings.size)
    }

    @Test
    fun `length prefix invalid length flushes raw and warns`() {
        val warnings = mutableListOf<String>()
        val f = FramingSpec.LengthPrefix(lengthFieldSize = 1, lengthAdjustment = -5).newFramer { warnings += it }
        assertEquals(listOf("\u0001abc"), f.feed(b(1) + s("abc")).strings())
        assertEquals(1, warnings.size)
    }

    @Test
    fun `invalid specs are rejected`() {
        assertThrows<IllegalArgumentException> { FramingSpec.LengthPrefix(lengthFieldSize = 5) }
        assertThrows<IllegalArgumentException> { FramingSpec.Delimiter(ByteArray(0)) }
    }
}
