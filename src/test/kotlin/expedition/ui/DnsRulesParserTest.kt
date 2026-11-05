package expedition.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class DnsRulesParserTest {

    @Test fun `parses host-ip lines, ignoring blanks and comments`() {
        val rules = DnsRulesParser.parse(
            """
            # a comment
            *.example.com   127.0.0.1

            api.test   10.0.0.5
            garbage-line-with-one-token
            """.trimIndent())
        assertEquals(2, rules.size)
        assertEquals("*.example.com", rules[0].hostPattern)
        assertEquals("127.0.0.1", rules[0].ip)
        assertEquals("api.test", rules[1].hostPattern)
        assertEquals("10.0.0.5", rules[1].ip)
    }
}
