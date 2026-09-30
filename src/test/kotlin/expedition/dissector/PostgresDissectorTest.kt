package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun pgMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class PostgresDissectorTest {

    private val d = PostgresDissector()

    // 'Q' Query: type 'Q' + Int32 length(13) + "SELECT 1" + NUL  (length counts itself + body)
    private val query = byteArrayOf('Q'.code.toByte(), 0x00, 0x00, 0x00, 0x0d) + "SELECT 1".toByteArray() + byteArrayOf(0x00)

    @Test
    fun `renders a Query message with the SQL text`() {
        val out = d.render(pgMsg(query))
        assertTrue(out.contains("PG Query"), out)
        assertTrue(out.contains("sql: SELECT 1"), out)
    }

    @Test
    fun `round-trips a Query message`() {
        val original = pgMsg(query)
        assertArrayEquals(query, d.parseEdit(d.render(original), original))
    }

    @Test
    fun `editing the SQL recomputes the length prefix`() {
        val edited = "PG Query\nsql: SELECT 2 FROM t"
        val out = d.parseEdit(edited, pgMsg(query))
        val sql = "SELECT 2 FROM t"
        val expected = byteArrayOf('Q'.code.toByte()) +
            intBytes(4 + sql.length + 1) + sql.toByteArray() + byteArrayOf(0x00)
        assertArrayEquals(expected, out)
    }

    @Test
    fun `renders a non-Query typed message and round-trips via raw hex`() {
        // 'Z' ReadyForQuery: type + len(5) + status 'I'
        val ready = byteArrayOf('Z'.code.toByte(), 0x00, 0x00, 0x00, 0x05, 'I'.code.toByte())
        val out = d.render(pgMsg(ready))
        assertTrue(out.contains("PG ReadyForQuery"), out)
        assertArrayEquals(ready, d.parseEdit(out, pgMsg(ready)))
    }

    @Test
    fun `parse rejects a length that would overflow instead of throwing`() {
        // 'Q' + length 0x7FFFFFFF — 1 + length overflows Int; must be rejected, not crash.
        assertFalse(d.supports(pgMsg(byteArrayOf('Q'.code.toByte(), 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()))))
    }

    @Test
    fun `round-trips a multi-line query without truncation`() {
        val sql = "SELECT id\nFROM t"
        val body = sql.toByteArray() + byteArrayOf(0)
        val bytes = byteArrayOf('Q'.code.toByte()) + intBytes(4 + body.size) + body
        assertArrayEquals(bytes, d.parseEdit(d.render(pgMsg(bytes)), pgMsg(bytes)))
    }

    @Test
    fun `supports a valid Postgres message and rejects non-Postgres`() {
        assertTrue(d.supports(pgMsg(query)))
        assertFalse(d.supports(pgMsg(byteArrayOf(1, 2, 3))))
        assertFalse(d.supports(pgMsg(byteArrayOf())))
        // length claims more than the buffer holds
        assertFalse(d.supports(pgMsg(byteArrayOf('Q'.code.toByte(), 0x00, 0x00, 0x00, 0x50, 0x41))))
    }

    private fun intBytes(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )
}
