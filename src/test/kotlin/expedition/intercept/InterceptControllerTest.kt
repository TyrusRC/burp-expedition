package expedition.intercept

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

class InterceptControllerTest {

    @Test
    fun `forwards immediately when intercept is disabled`() {
        val controller = InterceptController()

        val future = controller.intercept("hello".toByteArray()) { _, _ -> fail("should not hold") }

        val decision = future.get(1, TimeUnit.SECONDS) as InterceptDecision.Forward
        assertArrayEquals("hello".toByteArray(), decision.bytes)
    }

    @Test
    fun `holds the message until forward is called, then delivers edited bytes`() {
        val controller = InterceptController()
        controller.setEnabled(true)
        var heldId: Long = -1

        val future = controller.intercept("hello".toByteArray()) { id, _ -> heldId = id }

        assertFalse(future.isDone)
        controller.forward(heldId, "edited".toByteArray())

        val decision = future.get(1, TimeUnit.SECONDS) as InterceptDecision.Forward
        assertArrayEquals("edited".toByteArray(), decision.bytes)
    }

    @Test
    fun `drop resolves the future with Drop`() {
        val controller = InterceptController()
        controller.setEnabled(true)
        var heldId: Long = -1

        val future = controller.intercept("hello".toByteArray()) { id, _ -> heldId = id }
        controller.drop(heldId)

        assertEquals(InterceptDecision.Drop, future.get(1, TimeUnit.SECONDS))
    }

    @Test
    fun `each held message gets a distinct id`() {
        val controller = InterceptController()
        controller.setEnabled(true)
        val ids = mutableListOf<Long>()

        controller.intercept("a".toByteArray()) { id, _ -> ids.add(id) }
        controller.intercept("b".toByteArray()) { id, _ -> ids.add(id) }

        assertEquals(2, ids.toSet().size)
    }
}
