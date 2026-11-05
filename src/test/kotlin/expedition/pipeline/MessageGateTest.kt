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

    // I2: an exception anywhere in the forward chain must be recorded, not silently swallowed
    // into an unobserved future (which would drop the message and stall the direction).
    // Rule application can no longer throw at apply-time (MatchReplaceRule validates and
    // compiles at construction, and the regex engine fails safe), so the still-reachable
    // trigger is a throwing forward callback — e.g. the upstream write failing.
    @Test
    fun `records an error entry instead of silently dropping when the forward chain throws`() {
        val registry = ConnectionRegistry()
        val connectionId = registry.openConnection("l", Protocol.TCP, "c", "u")
        val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }

        gate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, "hi".toByteArray()) {
            throw RuntimeException("upstream write failed")
        }

        assertTrue(registry.messagesFor(connectionId).any { it.dissectedView?.startsWith("ERROR") == true })
    }

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
    fun `runs the script hook on forwarded bytes after match and replace`() {
        val registry = ConnectionRegistry()
        val connectionId = registry.openConnection("l", Protocol.TCP, "c", "u")
        val matchReplace = MatchReplaceEngine().apply { addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar")) }
        val hooks = expedition.script.ScriptHooks().apply { setScript("new String(bytes).toUpperCase().getBytes()") }
        val gate = MessageGate(registry, InterceptController(), matchReplace, hooks) { _, _, _, _ -> }
        var forwarded: ByteArray? = null

        gate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, "foo".toByteArray()) { forwarded = it }

        // match/replace foo->bar runs first, then the script upper-cases: "BAR"
        assertArrayEquals("BAR".toByteArray(), forwarded)
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
