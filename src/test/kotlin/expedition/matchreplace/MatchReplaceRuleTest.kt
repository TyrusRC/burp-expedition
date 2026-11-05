package expedition.matchreplace

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test

/**
 * A rule must be validated and its regex compiled WHEN THE RULE IS CREATED, not when
 * it is first applied. The Control API path (ControlApiServer.addRule) builds rules
 * directly, bypassing the UI form validator; an invalid pattern or malformed hex that
 * is only caught in apply() throws on a Netty worker thread and silently stalls that
 * traffic direction (MessageGate records ERROR and never forwards). Rejecting at
 * construction gives both paths a 400/validation failure instead.
 */
class MatchReplaceRuleTest {

    @Test
    fun `an invalid regex is rejected at construction`() {
        assertThrows<IllegalArgumentException> {
            MatchReplaceRule(1, MatchType.REGEX, "(unclosed", "x")
        }
    }

    @Test
    fun `an odd-length hex literal-bytes match is rejected at construction`() {
        assertThrows<IllegalArgumentException> {
            MatchReplaceRule(1, MatchType.LITERAL_BYTES, "abc", "ff")
        }
    }

    @Test
    fun `a non-hex literal-bytes replacement is rejected at construction`() {
        assertThrows<IllegalArgumentException> {
            MatchReplaceRule(1, MatchType.LITERAL_BYTES, "0102", "zz")
        }
    }

    @Test
    fun `a valid regex rule exposes a precompiled regex so apply never recompiles`() {
        val rule = MatchReplaceRule(1, MatchType.REGEX, "\\d+", "N")
        assertNotNull(rule.regex)
        assertEquals("id=N", rule.regex!!.replace("id=42", "N"))
    }

    @Test
    fun `a non-regex rule has no compiled regex`() {
        assertNull(MatchReplaceRule(1, MatchType.LITERAL_STRING, "a", "b").regex)
    }
}
