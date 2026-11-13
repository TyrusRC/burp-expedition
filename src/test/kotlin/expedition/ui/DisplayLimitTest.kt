package expedition.ui

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class DisplayLimitTest {
    @Test fun `short text untouched`() = assertFalse(DisplayLimit.truncate("abc").truncated)
    @Test fun `long text truncated with size note`() {
        val s = DisplayLimit.truncate("x".repeat(100), maxChars = 10, totalBytes = 100)
        assertTrue(s.truncated); assertTrue(s.text.contains("100 bytes"))
    }
    @Test fun `joinBounded stops early`() {
        val s = DisplayLimit.joinBounded(generateSequence { "y".repeat(50) }.take(1000), maxChars = 200)
        assertTrue(s.truncated); assertTrue(s.text.length < 400)
    }

    @Test
    fun `toggleIntercept applies on then off in order and reports real state`() {
        val controller = expedition.intercept.InterceptController()
        val ex = java.util.concurrent.Executors.newSingleThreadExecutor()
        val results = java.util.Collections.synchronizedList(mutableListOf<Boolean>())
        val done = java.util.concurrent.CountDownLatch(2)
        DisplayLimit.toggleIntercept(ex, controller, true) { results.add(it); done.countDown() }
        DisplayLimit.toggleIntercept(ex, controller, false) { results.add(it); done.countDown() }
        assertTrue(done.await(5, java.util.concurrent.TimeUnit.SECONDS))
        ex.shutdown()
        assertEquals(listOf(true, false), results.toList())
        assertFalse(controller.isEnabled())
    }
}
