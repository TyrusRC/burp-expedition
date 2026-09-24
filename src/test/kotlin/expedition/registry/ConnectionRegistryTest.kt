package expedition.registry

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ConnectionRegistryTest {

    @Test
    fun `opens a connection and records messages in order`() {
        val registry = ConnectionRegistry()
        val id = registry.openConnection("test-listener", Protocol.TCP, "127.0.0.1:1234", "127.0.0.1:80")

        registry.recordMessage(id, Direction.CLIENT_TO_UPSTREAM, "hello".toByteArray())
        registry.recordMessage(id, Direction.UPSTREAM_TO_CLIENT, "world".toByteArray())

        val messages = registry.messagesFor(id)
        assertEquals(2, messages.size)
        assertEquals(Direction.CLIENT_TO_UPSTREAM, messages[0].direction)
        assertArrayEquals("hello".toByteArray(), messages[0].rawBytes)
        assertEquals(Direction.UPSTREAM_TO_CLIENT, messages[1].direction)

        val summary = registry.connection(id)
        assertNotNull(summary)
        assertEquals("test-listener", summary!!.listenerName)
        assertNull(summary.closedAt)
    }

    @Test
    fun `closing a connection sets closedAt`() {
        val registry = ConnectionRegistry()
        val id = registry.openConnection("l", Protocol.UDP, "c", "u")

        registry.closeConnection(id)

        assertNotNull(registry.connection(id)!!.closedAt)
    }

    @Test
    fun `allMessages spans multiple connections in recording order`() {
        val registry = ConnectionRegistry()
        val a = registry.openConnection("l", Protocol.TCP, "c1", "u")
        val b = registry.openConnection("l", Protocol.TCP, "c2", "u")

        registry.recordMessage(a, Direction.CLIENT_TO_UPSTREAM, byteArrayOf(1))
        registry.recordMessage(b, Direction.CLIENT_TO_UPSTREAM, byteArrayOf(2))

        assertEquals(listOf(a, b), registry.allMessages().map { it.connectionId })
    }
}
