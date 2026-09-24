package expedition.pipeline

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MessageGateTest {

    @Test
    fun `forwards immediately and records history when intercept is disabled`() {
        val registry = ConnectionRegistry()
        val connectionId = registry.openConnection("l", Protocol.TCP, "c", "u")
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
        var forwarded: ByteArray? = null

        gate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, "hello".toByteArray()) { forwarded = it }

        assertArrayEquals("hello".toByteArray(), forwarded)
        assertEquals(1, registry.messagesFor(connectionId).size)
    }

    @Test
    fun `applies match and replace rules before forwarding`() {
        val registry = ConnectionRegistry()
        val connectionId = registry.openConnection("l", Protocol.TCP, "c", "u")
        val matchReplace = MatchReplaceEngine().apply { addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar")) }
        val gate = MessageGate(registry, InterceptController(), matchReplace) { _, _, _, _ -> }
        var forwarded: ByteArray? = null

        gate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, "foo".toByteArray()) { forwarded = it }

        assertArrayEquals("bar".toByteArray(), forwarded)
    }

    @Test
    fun `holds the message and only forwards edited bytes once the controller forwards it`() {
        val registry = ConnectionRegistry()
        val connectionId = registry.openConnection("l", Protocol.TCP, "c", "u")
        val intercept = InterceptController().apply { setEnabled(true) }
        var heldId = -1L
        val gate = MessageGate(registry, intercept, MatchReplaceEngine()) { id, _, _, _ -> heldId = id }
        var forwarded: ByteArray? = null

        gate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, "orig".toByteArray()) { forwarded = it }
        assertNull(forwarded)

        intercept.forward(heldId, "edited".toByteArray())
        assertArrayEquals("edited".toByteArray(), forwarded)
    }

    @Test
    fun `records a DROPPED entry and never forwards when the controller drops the message`() {
        val registry = ConnectionRegistry()
        val connectionId = registry.openConnection("l", Protocol.TCP, "c", "u")
        val intercept = InterceptController().apply { setEnabled(true) }
        var heldId = -1L
        val gate = MessageGate(registry, intercept, MatchReplaceEngine()) { id, _, _, _ -> heldId = id }
        var forwardCalled = false

        gate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, "orig".toByteArray()) { forwardCalled = true }
        intercept.drop(heldId)

        assertFalse(forwardCalled)
        assertEquals("DROPPED", registry.messagesFor(connectionId).single().dissectedView)
    }
}
