package expedition.intercept

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

sealed class InterceptDecision {
    data class Forward(val bytes: ByteArray) : InterceptDecision()
    object Drop : InterceptDecision()
}

/** A message currently held for the operator, exposed to the control API. */
data class HeldMessage(val id: Long, val connectionId: Long, val direction: String, val bytes: ByteArray)

class InterceptController {
    @Volatile
    private var interceptEnabled = false
    private val pending = ConcurrentHashMap<Long, CompletableFuture<InterceptDecision>>()
    private val held = ConcurrentHashMap<Long, HeldMessage>()
    private val nextId = AtomicLong(1)

    fun setEnabled(enabled: Boolean) {
        interceptEnabled = enabled
    }

    fun isEnabled(): Boolean = interceptEnabled

    fun intercept(rawBytes: ByteArray, onHeld: (heldMessageId: Long, bytes: ByteArray) -> Unit): CompletableFuture<InterceptDecision> {
        if (!interceptEnabled) {
            return CompletableFuture.completedFuture(InterceptDecision.Forward(rawBytes))
        }
        val id = nextId.getAndIncrement()
        val future = CompletableFuture<InterceptDecision>()
        pending[id] = future
        onHeld(id, rawBytes)
        return future
    }

    /** Record held-message metadata so the control API can list/forward/drop it.
     *  Called by MessageGate, which knows the connection + direction. */
    fun recordHeld(id: Long, connectionId: Long, direction: String, bytes: ByteArray) {
        if (pending.containsKey(id)) held[id] = HeldMessage(id, connectionId, direction, bytes)
    }

    /** Snapshot of currently-held messages (for the control API). */
    fun heldMessages(): List<HeldMessage> = held.values.sortedBy { it.id }

    /** The original bytes of a held message, or null if it is not held. */
    fun heldBytes(id: Long): ByteArray? = held[id]?.bytes

    fun forward(heldMessageId: Long, editedBytes: ByteArray) {
        held.remove(heldMessageId)
        pending.remove(heldMessageId)?.complete(InterceptDecision.Forward(editedBytes))
    }

    fun drop(heldMessageId: Long) {
        held.remove(heldMessageId)
        pending.remove(heldMessageId)?.complete(InterceptDecision.Drop)
    }
}
