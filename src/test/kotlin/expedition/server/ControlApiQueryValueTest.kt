package expedition.server

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test

class ControlApiQueryValueTest {

    @Test
    fun `absent key or empty query yields null`() {
        assertNull(ControlApiServer.queryValue(null, "q"))
        assertNull(ControlApiServer.queryValue("", "q"))
        assertNull(ControlApiServer.queryValue("limit=5", "q"))
    }

    @Test
    fun `plus is a space and percent escapes are utf-8 decoded`() {
        assertEquals("a b", ControlApiServer.queryValue("q=a+b", "q"))
        assertEquals("a+b", ControlApiServer.queryValue("q=a%2Bb", "q"))
        assertEquals("100%", ControlApiServer.queryValue("q=100%25", "q"))
        assertEquals("héllo", ControlApiServer.queryValue("q=h%C3%A9llo", "q"))
        assertEquals("日本", ControlApiServer.queryValue("q=%E6%97%A5%E6%9C%AC", "q"))
    }

    @Test
    fun `picks the requested key among several params`() {
        assertEquals("x y", ControlApiServer.queryValue("limit=3&q=x+y&other=1", "q"))
        assertEquals("3", ControlApiServer.queryValue("limit=3&q=x+y", "limit"))
    }

    @Test
    fun `key match is exact not a suffix match`() {
        assertNull(ControlApiServer.queryValue("xq=1", "q"))
    }

    @Test
    fun `empty value decodes to empty string`() {
        assertEquals("", ControlApiServer.queryValue("q=", "q"))
    }

    @Test
    fun `malformed percent escape is rejected`() {
        assertThrows<IllegalArgumentException> { ControlApiServer.queryValue("q=%zz", "q") }
    }
}
