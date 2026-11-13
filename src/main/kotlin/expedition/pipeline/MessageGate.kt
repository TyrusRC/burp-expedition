package expedition.pipeline

import expedition.intercept.InterceptController
import expedition.intercept.InterceptDecision
import expedition.intercept.StreamKey
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction

class MessageGate(
    private val registry: ConnectionRegistry,
    private val interceptController: InterceptController,
    private val matchReplaceEngine: MatchReplaceEngine,
    private val scriptHooks: expedition.script.ScriptHooks? = null,
    private val onHeldMessage: (heldMessageId: Long, connectionId: Long, direction: Direction, bytes: ByteArray) -> Unit
) {
    /** Optional declarative HTTP rules layer (expedition.rules); null = not installed. */
    @Volatile var rulesEngine: expedition.rules.RulesEngine? = null
    private val ruleSessions = expedition.rules.RuleSessions(
        ::processCore,
        { c, d, b, n -> registry.recordMessage(c, d, b, n) },
        { c, d, b -> registry.recordMessage(c, d, b) },
    )
    fun attachConnection(connectionId: Long, control: expedition.rules.ConnectionControl) = ruleSessions.attach(connectionId, control)
    fun detachConnection(connectionId: Long) {
        ruleSessions.detach(connectionId)
        // Messages of this connection still held for the operator can never be delivered now.
        interceptController.discardConnection(connectionId)
    }

    /** True when a new connection on [listenerName] should dial its upstream lazily (active mock rule). */
    fun wantsLazyDial(listenerName: String): Boolean = rulesEngine?.hasActiveLocalAnswer(listenerName) == true

    /**
     * ALPN list a MITM connection on [listenerName] offers upstream (and so may select for the
     * client). While ANY HTTP rule is active for the listener the rules layer must see HTTP/1.x,
     * so only `http/1.1` is offered (when the client offered it; an h2-only client keeps its list
     * and the rules layer notes the bypass). Without active rules the client's list is passed
     * through and h2 is relayed as bytes.
     */
    fun mitmAlpn(listenerName: String, clientAlpn: List<String>): List<String> =
        if (rulesEngine?.hasActive(null, listenerName) == true && "http/1.1" in clientAlpn) listOf("http/1.1") else clientAlpn

    fun process(connectionId: Long, direction: Direction, bytes: ByteArray, forward: (ByteArray) -> Unit) {
        val engine = rulesEngine
        if (engine != null && ruleSessions.process(engine, connectionId, direction, bytes, forward)) return
        processCore(connectionId, direction, bytes, forward, false)
    }

    private fun processCore(connectionId: Long, direction: Direction, bytes: ByteArray, forward: (ByteArray) -> Unit, forceHold: Boolean) {
        // Keyed by (connection, direction) so the controller releases decisions FIFO per stream:
        // forwarding a later held message first can never reorder bytes on the wire.
        interceptController.submit(
            StreamKey(connectionId, direction.name), connectionId, direction.name, bytes,
            onHeld = { heldId, heldBytes -> onHeldMessage(heldId, connectionId, direction, heldBytes) },
            forceHold = forceHold,
        ) { decision ->
            try {
                when (decision) {
                    is InterceptDecision.Drop ->
                        registry.recordMessage(connectionId, direction, ByteArray(0), "DROPPED")
                    is InterceptDecision.Forward -> {
                        val replaced = matchReplaceEngine.apply(decision.bytes, direction)
                        val finalBytes = scriptHooks?.transform(connectionId, direction.name, replaced) ?: replaced
                        registry.recordMessage(connectionId, direction, finalBytes)
                        forward(finalBytes)
                    }
                }
            } catch (error: Exception) {
                // Without this, a failure in rule application or the forward callback would drop
                // the message with no trace. Record it so it is visible in history.
                registry.recordMessage(connectionId, direction, ByteArray(0), "ERROR: ${error.message}")
            }
        }
    }

    /** Record an informational entry (e.g. a framing warning) in the connection's history. */
    fun recordNote(connectionId: Long, direction: Direction, note: String) {
        registry.recordMessage(connectionId, direction, ByteArray(0), note)
    }
}
