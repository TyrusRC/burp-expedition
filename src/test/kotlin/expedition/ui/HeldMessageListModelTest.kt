package expedition.ui

import expedition.registry.Direction
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class HeldMessageListModelTest {

    @Test
    fun `add appends an entry and getSize reflects it`() {
        val model = HeldMessageListModel()
        model.add(HeldMessageListModel.Entry(1, 10, Direction.CLIENT_TO_UPSTREAM, "a".toByteArray()))

        assertEquals(1, model.size)
        assertEquals(1L, model.getElementAt(0).heldMessageId)
    }

    @Test
    fun `removeById removes the matching entry and preserves order of the rest`() {
        val model = HeldMessageListModel()
        model.add(HeldMessageListModel.Entry(1, 10, Direction.CLIENT_TO_UPSTREAM, "a".toByteArray()))
        model.add(HeldMessageListModel.Entry(2, 10, Direction.CLIENT_TO_UPSTREAM, "b".toByteArray()))
        model.add(HeldMessageListModel.Entry(3, 10, Direction.CLIENT_TO_UPSTREAM, "c".toByteArray()))

        model.removeById(2)

        assertEquals(2, model.size)
        assertEquals(1L, model.getElementAt(0).heldMessageId)
        assertEquals(3L, model.getElementAt(1).heldMessageId)
    }

    @Test
    fun `removeById is a no-op for an unknown id`() {
        val model = HeldMessageListModel()
        model.add(HeldMessageListModel.Entry(1, 10, Direction.CLIENT_TO_UPSTREAM, "a".toByteArray()))

        model.removeById(999)

        assertEquals(1, model.size)
    }
}
