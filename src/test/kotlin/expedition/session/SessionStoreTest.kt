package expedition.session

import expedition.registry.ConnectionSummary
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

class SessionStoreTest {

    @Test
    fun `exports and re-imports a session snapshot`() {
        val t = Instant.ofEpochMilli(1_700_000_000_000)
        val conns = listOf(
            ConnectionSummary(1, "l", Protocol.TCP, "c", "u", t, null),
            ConnectionSummary(2, "l2", Protocol.UDP, "c2", "u2", t, t)
        )
        val msgs = listOf(
            ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, t, byteArrayOf(1, 2, 3), null),
            ProxyMessage(2, 1, Direction.UPSTREAM_TO_CLIENT, t, "hi".toByteArray(), "DROPPED")
        )
        val tags = mapOf(1L to setOf("a", "b"), 2L to setOf("c"))

        val json = SessionStore.export(SessionSnapshot(conns, msgs, tags))
        val back = SessionStore.import(json)

        assertEquals(conns, back.connections)
        assertEquals(tags, back.tags)
        assertEquals(2, back.messages.size)
        back.messages.forEachIndexed { i, m ->
            assertEquals(msgs[i].id, m.id)
            assertEquals(msgs[i].connectionId, m.connectionId)
            assertEquals(msgs[i].direction, m.direction)
            assertArrayEquals(msgs[i].rawBytes, m.rawBytes)
            assertEquals(msgs[i].dissectedView, m.dissectedView)
        }
    }
}
