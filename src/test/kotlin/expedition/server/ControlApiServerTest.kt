package expedition.server

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JsonTest {

    @Test
    fun `writes and escapes primitives`() {
        assertEquals("""{"a":1,"b":"x\"y","c":true,"d":null}""",
            Json.obj("a" to 1, "b" to "x\"y", "c" to true, "d" to null))
        assertEquals("""[1,"a",false]""", Json.arr(listOf(1, "a", false)))
    }

    @Test
    fun `parses flat object with typed reads`() {
        val o = Json.asObject(Json.parse("""{"name":"redis","port":6379,"tls":true}"""))
        assertEquals("redis", Json.str(o, "name"))
        assertEquals(6379, Json.int(o, "port"))
        assertEquals(true, o["tls"])
        assertEquals(0, Json.int(o, "missing"))
    }

    @Test
    fun `parses nested and escaped strings`() {
        val o = Json.asObject(Json.parse("""{"a":{"b":[1,2]},"s":"line\nbreak"}"""))
        assertTrue(o["a"] is Map<*, *>)
        assertEquals("line\nbreak", o["s"])
    }
}

class ControlApiHelpersTest {

    @Test
    fun `loopback host check is dns-rebind safe`() {
        assertTrue(ControlApiServer.isLoopback("127.0.0.1"))
        assertTrue(ControlApiServer.isLoopback("localhost"))
        assertTrue(ControlApiServer.isLoopback("::1"))
        // a rebinding hostname pointed at loopback must NOT pass
        assertFalse(ControlApiServer.isLoopback("127.0.0.1.evil.com"))
        assertFalse(ControlApiServer.isLoopback("evil.com"))
        assertFalse(ControlApiServer.isLoopback("10.0.0.5"))
    }

    @Test
    fun `hex round-trips`() {
        val bytes = byteArrayOf(0x00, 0x2a, 0x7f, 0xff.toByte())
        assertEquals("002a7fff", ControlApiServer.toHex(bytes))
        assertArrayEquals(bytes, ControlApiServer.fromHex("00 2a 7f ff"))
    }

    @Test
    fun `preview masks non-printable`() {
        assertEquals("AB..", ControlApiServer.preview(byteArrayOf(0x41, 0x42, 0x00, 0x1f)))
    }
}
