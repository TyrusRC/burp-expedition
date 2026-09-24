package expedition.intercept

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

sealed class InterceptDecision {
    data class Forward(val bytes: ByteArray) : InterceptDecision()
    object Drop : InterceptDecision()
}

class InterceptController {
    @Volatile
    private var interceptEnabled = false
    private val pending = ConcurrentHashMap<Long, CompletableFuture<InterceptDecision>>()
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

    fun forward(heldMessageId: Long, editedBytes: ByteArray) {
        pending.remove(heldMessageId)?.complete(InterceptDecision.Forward(editedBytes))
    }

    fun drop(heldMessageId: Long) {
        pending.remove(heldMessageId)?.complete(InterceptDecision.Drop)
    }
}
