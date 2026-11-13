package expedition.rules

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SafeRegexCapTest {
    @Test fun `budget is capped for huge inputs`() = assertEquals(SafeRegex.MAX_STEPS, SafeRegex.budget(16 shl 20))

    @Test fun `catastrophic regex on large input finishes fast`() {
        val text = "a".repeat(200_000) + "!"
        val t0 = System.nanoTime()
        assertFalse(SafeRegex.containsMatch(Regex("^(a+)+$"), text))
        assertEquals(text, SafeRegex.replace(Regex("(a+)+$"), text, "x"))
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 5_000)
    }
}
