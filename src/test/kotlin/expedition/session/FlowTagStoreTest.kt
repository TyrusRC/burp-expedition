package expedition.session

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class FlowTagStoreTest {

    @Test
    fun `tags and reads tags for a connection`() {
        val store = FlowTagStore()
        store.tag(1, "sqli")
        store.tag(1, "interesting")
        assertEquals(setOf("sqli", "interesting"), store.tags(1))
    }

    @Test
    fun `untag removes a single tag`() {
        val store = FlowTagStore()
        store.tag(1, "a"); store.tag(1, "b")
        store.untag(1, "a")
        assertEquals(setOf("b"), store.tags(1))
    }

    @Test
    fun `taggedWith lists connections carrying a tag, sorted`() {
        val store = FlowTagStore()
        store.tag(3, "x"); store.tag(1, "x"); store.tag(2, "y")
        assertEquals(listOf(1L, 3L), store.taggedWith("x"))
    }

    @Test
    fun `tags of an unknown connection is empty`() {
        assertTrue(FlowTagStore().tags(99).isEmpty())
    }

    @Test
    fun `all returns a snapshot of every tagged connection`() {
        val store = FlowTagStore()
        store.tag(1, "a"); store.tag(2, "b")
        assertEquals(mapOf(1L to setOf("a"), 2L to setOf("b")), store.all())
    }
}
