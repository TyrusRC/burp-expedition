package expedition.registry

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ConnectionRegistryLimitsTest {

    @Test
    fun `byte budget evicts the oldest messages first`() {
        val registry = ConnectionRegistry(maxBytes = 10)
        val c = registry.openConnection("l", Protocol.TCP, "c", "u")

        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, ByteArray(4) { 1 })
        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, ByteArray(4) { 2 })
        assertEquals(8L, registry.retainedMessageBytes())

        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, ByteArray(4) { 3 })
        // 12 > 10: the oldest (4 bytes of 1) goes, leaving 8 bytes.
        assertEquals(8L, registry.retainedMessageBytes())
        val kept = registry.allMessages().map { it.rawBytes.first() }
        assertEquals(listOf<Byte>(2, 3), kept)
    }

    @Test
    fun `newest message is kept even when it alone exceeds the byte budget`() {
        val registry = ConnectionRegistry(maxBytes = 4)
        val c = registry.openConnection("l", Protocol.TCP, "c", "u")

        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, ByteArray(2))
        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, ByteArray(9) { 7 })

        assertEquals(1, registry.allMessages().size)
        assertArrayEquals(ByteArray(9) { 7 }, registry.allMessages().single().rawBytes)
    }

    @Test
    fun `closed connections are capped and the least recently closed go first`() {
        val registry = ConnectionRegistry(maxClosedConnections = 2)
        val ids = (1..4).map { registry.openConnection("l", Protocol.TCP, "c$it", "u") }
        val open = registry.openConnection("l", Protocol.TCP, "still-open", "u")

        ids.forEach { registry.closeConnection(it) }

        assertNull(registry.connection(ids[0]))
        assertNull(registry.connection(ids[1]))
        assertNotNull(registry.connection(ids[2])!!.closedAt)
        assertNotNull(registry.connection(ids[3])!!.closedAt)
        assertNull(registry.connection(open)!!.closedAt, "open connections are never evicted")
    }

    @Test
    fun `double close does not count the connection twice`() {
        val registry = ConnectionRegistry(maxClosedConnections = 1)
        val a = registry.openConnection("l", Protocol.TCP, "a", "u")
        val b = registry.openConnection("l", Protocol.TCP, "b", "u")

        registry.closeConnection(a)
        registry.closeConnection(a)
        registry.closeConnection(b)

        assertNull(registry.connection(a))
        assertNotNull(registry.connection(b))
    }

    @Test
    fun `default constructor keeps the original behaviour`() {
        val registry = ConnectionRegistry()
        val c = registry.openConnection("l", Protocol.TCP, "c", "u")
        registry.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, "hi".toByteArray())
        assertEquals(2L, registry.retainedMessageBytes())
        assertNotNull(registry.connection(c))
    }
}
