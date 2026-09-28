package expedition.ui

import expedition.matchreplace.MatchType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MatchReplaceFormValidationTest {

    @Test
    fun `accepts a literal string rule`() {
        val result = MatchReplaceFormValidation.validate(MatchType.LITERAL_STRING, "foo", "bar", 1)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `accepts a valid regex rule`() {
        val result = MatchReplaceFormValidation.validate(MatchType.REGEX, "\\d+", "N", 1)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `rejects an invalid regex`() {
        val result = MatchReplaceFormValidation.validate(MatchType.REGEX, "(unclosed", "N", 1)
        assertTrue(result.isFailure)
    }

    @Test
    fun `accepts literal bytes expressed as hex pairs`() {
        val result = MatchReplaceFormValidation.validate(MatchType.LITERAL_BYTES, "48 65", "00", 1)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `rejects literal bytes that are not valid hex pairs`() {
        val result = MatchReplaceFormValidation.validate(MatchType.LITERAL_BYTES, "not-hex", "00", 1)
        assertTrue(result.isFailure)
    }

    @Test
    fun `rejects a blank match value`() {
        val result = MatchReplaceFormValidation.validate(MatchType.LITERAL_STRING, "", "bar", 1)
        assertTrue(result.isFailure)
    }
}
