package expedition.pipeline

import expedition.intercept.InterceptController
import expedition.intercept.InterceptDecision
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction

class MessageGate(
    private val registry: ConnectionRegistry,
    private val interceptController: InterceptController,
    private val matchReplaceEngine: MatchReplaceEngine,
    private val onHeldMessage: (heldMessageId: Long, connectionId: Long, direction: Direction, bytes: ByteArray) -> Unit
) {
    fun process(connectionId: Long, direction: Direction, bytes: ByteArray, forward: (ByteArray) -> Unit) {
        interceptController.intercept(bytes) { heldId, heldBytes ->
            interceptController.recordHeld(heldId, connectionId, direction.name, heldBytes)
            onHeldMessage(heldId, connectionId, direction, heldBytes)
        }.thenAccept { decision ->
            when (decision) {
                is InterceptDecision.Drop ->
                    registry.recordMessage(connectionId, direction, ByteArray(0), "DROPPED")
                is InterceptDecision.Forward -> {
                    val finalBytes = matchReplaceEngine.apply(decision.bytes)
                    registry.recordMessage(connectionId, direction, finalBytes)
                    forward(finalBytes)
                }
            }
        }.whenComplete { _, error ->
            // Without this, any failure in rule application or the forward callback would
            // complete the future exceptionally and be silently swallowed — the message
            // dropped and that direction stalled with no trace. Record it so it is visible.
            if (error != null) {
                registry.recordMessage(connectionId, direction, ByteArray(0), "ERROR: ${error.cause?.message ?: error.message}")
            }
        }
    }
}
