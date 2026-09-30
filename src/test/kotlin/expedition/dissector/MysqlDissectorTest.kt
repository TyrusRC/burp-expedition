package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun myMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class MysqlDissectorTest {

    private val d = MysqlDissector()

    // COM_QUERY: 4-byte header (len=9 LE, seq=0) + 0x03 + "SELECT 1"
    private val query = byteArrayOf(0x09, 0x00, 0x00, 0x00, 0x03) + "SELECT 1".toByteArray()

    @Test
    fun `renders a COM_QUERY with the SQL`() {
        val out = d.render(myMsg(query))
        assertTrue(out.contains("MySQL Query"), out)
        assertTrue(out.contains("sql: SELECT 1"), out)
    }

    @Test
    fun `round-trips a COM_QUERY`() {
        assertArrayEquals(query, d.parseEdit(d.render(myMsg(query)), myMsg(query)))
    }

    @Test
    fun `editing the SQL recomputes the packet length`() {
        val out = d.parseEdit("MySQL Query\nsql: SELECT 2 FROM t", myMsg(query))
        val sql = "SELECT 2 FROM t"
        val len = 1 + sql.length // 0x03 + sql
        val expected = byteArrayOf((len and 0xff).toByte(), 0x00, 0x00, 0x00, 0x03) + sql.toByteArray()
        assertArrayEquals(expected, out)
    }

    @Test
    fun `supports a valid MySQL packet and rejects non-MySQL`() {
        assertTrue(d.supports(myMsg(query)))
        assertFalse(d.supports(myMsg(byteArrayOf())))
        assertFalse(d.supports(myMsg(byteArrayOf(1, 2))))
        // length header claims 200 bytes, buffer has few
        assertFalse(d.supports(myMsg(byteArrayOf(0xc8.toByte(), 0x00, 0x00, 0x00, 0x03))))
    }
}
