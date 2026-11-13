package expedition.intercept

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap

sealed class InterceptDecision {
    data class Forward(val bytes: ByteArray) : InterceptDecision()
    object Drop : InterceptDecision()
}

/** A message currently held for the operator, exposed to the control API. */
data class HeldMessage(val id: Long, val connectionId: Long, val direction: String, val bytes: ByteArray)

/** Identifies one ordered stream (one direction of one connection); messages on it are released FIFO. */
data class StreamKey(val connectionId: Long, val direction: String)

/**
 * Holds messages for the operator and releases decisions in FIFO order per stream.
 *
 * Ordering: every message submitted on a [StreamKey] while that stream has anything outstanding
 * is queued behind it. A decision (forward/drop) on a later message is remembered but only
 * delivered once every earlier message on the same stream has been delivered, so forwarding #2
 * before #1 can never reorder the bytes on the wire.
 *
 * Concurrency: all queue/held/flag state is guarded by [lock]; decision callbacks (match &
 * replace, socket writes) run OUTSIDE the lock, with a per-stream `draining` flag ensuring only
 * one thread delivers a given stream at a time. Entries are popped only after their callback has
 * run, so a newer message can never overtake one that is mid-delivery.
 */
class InterceptController {
    @Volatile
    private var interceptEnabled = false

    private class Entry(val id: Long, val raw: ByteArray, val onDecision: (InterceptDecision) -> Unit) {
        var decision: InterceptDecision? = null // guarded by lock
    }

    private class Stream(val key: Any) {
        val queue = ArrayDeque<Entry>() // guarded by lock
        var draining = false            // guarded by lock
    }

    private val lock = Any()
    private val streams = HashMap<Any, Stream>()            // guarded by lock
    private val pending = HashMap<Long, Pair<Stream, Entry>>() // undecided held entries, guarded by lock
    private val held = ConcurrentHashMap<Long, HeldMessage>()  // read lock-free by the UI / API
    private var nextId = 1L                                     // guarded by lock

    fun setEnabled(enabled: Boolean) {
        val toDrain: List<Stream>
        synchronized(lock) {
            interceptEnabled = enabled
            if (enabled) return
            // Turning intercept OFF releases everything still undecided — otherwise those
            // connections stall forever (Burp forwards held items on toggle-off too). Done under
            // the same lock intercept uses to enqueue, so no just-held message can be missed.
            for ((_, ref) in pending) ref.second.decision = InterceptDecision.Forward(ref.second.raw)
            toDrain = pending.values.map { it.first }.distinct()
            pending.clear()
            held.clear()
        }
        toDrain.forEach(::drain)
    }

    fun isEnabled(): Boolean = interceptEnabled

    /**
     * Submit a message on [key]. [onDecision] is invoked exactly once (possibly synchronously,
     * possibly later from the thread that forwards/drops it), in FIFO order per key.
     * [onHeld] is called if the message is held for the operator.
     */
    fun submit(
        key: Any,
        connectionId: Long,
        direction: String,
        rawBytes: ByteArray,
        onHeld: (heldMessageId: Long, bytes: ByteArray) -> Unit,
        /** Hold this message even while intercept is off (rule breakpoints). */
        forceHold: Boolean = false,
        onDecision: (InterceptDecision) -> Unit,
    ) {
        var heldId = -1L
        val stream: Stream? = synchronized(lock) {
            val existing = streams[key]
            if (!interceptEnabled && !forceHold && existing == null) {
                null // nothing outstanding on this stream: fast path, no queue needed
            } else {
                val stream = existing ?: Stream(key).also { streams[key] = it }
                if (interceptEnabled || forceHold) {
                    heldId = nextId++
                    val entry = Entry(heldId, rawBytes, onDecision)
                    stream.queue.addLast(entry)
                    pending[heldId] = stream to entry
                    held[heldId] = HeldMessage(heldId, connectionId, direction, rawBytes)
                } else {
                    // Intercept is off but earlier messages on this stream are still queued:
                    // wait behind them, pre-decided.
                    stream.queue.addLast(Entry(-1, rawBytes, onDecision).also { it.decision = InterceptDecision.Forward(rawBytes) })
                }
                stream
            }
        }
        when {
            stream == null -> deliver(onDecision, InterceptDecision.Forward(rawBytes))
            heldId > 0 -> onHeld(heldId, rawBytes)
            else -> drain(stream)
        }
    }

    /**
     * Legacy, unordered form: each call is its own stream. Prefer [submit] with a [StreamKey].
     */
    fun intercept(rawBytes: ByteArray, onHeld: (heldMessageId: Long, bytes: ByteArray) -> Unit): CompletableFuture<InterceptDecision> {
        val future = CompletableFuture<InterceptDecision>()
        submit(Any(), -1, "", rawBytes, onHeld) { future.complete(it) }
        return future
    }

    /** Ordered future form: like [submit] but returns the decision as a future. */
    fun intercept(key: Any, rawBytes: ByteArray, onHeld: (heldMessageId: Long, bytes: ByteArray) -> Unit): CompletableFuture<InterceptDecision> {
        val future = CompletableFuture<InterceptDecision>()
        val (connId, dir) = (key as? StreamKey)?.let { it.connectionId to it.direction } ?: (-1L to "")
        submit(key, connId, dir, rawBytes, onHeld) { future.complete(it) }
        return future
    }

    /** Update held-message metadata (kept for callers of the legacy [intercept]). */
    fun recordHeld(id: Long, connectionId: Long, direction: String, bytes: ByteArray) {
        held.computeIfPresent(id) { _, _ -> HeldMessage(id, connectionId, direction, bytes) }
    }

    /** Snapshot of currently-held (undecided) messages, oldest first (for the control API). */
    fun heldMessages(): List<HeldMessage> = held.values.sortedBy { it.id }

    /** The original bytes of a held message, or null if it is not held. */
    fun heldBytes(id: Long): ByteArray? = held[id]?.bytes

    /**
     * The connection [connectionId] is gone: its still-held messages can never be delivered, so
     * they are decided as [InterceptDecision.Drop] (recorded, not forwarded) and leave the held
     * list. Messages queued behind them on the same stream drain normally. No-op when none.
     */
    fun discardConnection(connectionId: Long) {
        val toDrain: List<Stream>
        synchronized(lock) {
            val ids = held.values.filter { it.connectionId == connectionId }.map { it.id }
            if (ids.isEmpty()) return
            val streamsHit = LinkedHashSet<Stream>()
            for (id in ids) {
                held.remove(id)
                val (stream, entry) = pending.remove(id) ?: continue
                entry.decision = InterceptDecision.Drop
                streamsHit += stream
            }
            toDrain = streamsHit.toList()
        }
        toDrain.forEach(::drain)
    }

    fun forward(heldMessageId: Long, editedBytes: ByteArray) = decide(heldMessageId, InterceptDecision.Forward(editedBytes))

    fun drop(heldMessageId: Long) = decide(heldMessageId, InterceptDecision.Drop)

    private fun decide(id: Long, decision: InterceptDecision) {
        val stream = synchronized(lock) {
            val (stream, entry) = pending.remove(id) ?: return // unknown or already decided: no-op
            held.remove(id)
            entry.decision = decision
            stream
        }
        drain(stream)
    }

    /** Deliver decided entries from the head of [stream] in order, stopping at the first undecided one. */
    private fun drain(stream: Stream) {
        while (true) {
            val head: Entry
            val decision: InterceptDecision
            synchronized(lock) {
                if (stream.draining) return // another thread is delivering this stream; it will pick ours up
                val h = stream.queue.firstOrNull()
                if (h == null) {
                    if (streams[stream.key] === stream) streams.remove(stream.key)
                    return
                }
                if (h.decision == null) return
                stream.draining = true
                head = h
                decision = h.decision!!
            }
            try {
                deliver(head.onDecision, decision)
            } finally {
                synchronized(lock) {
                    stream.queue.removeFirst()
                    stream.draining = false
                }
            }
        }
    }

    private fun deliver(onDecision: (InterceptDecision) -> Unit, decision: InterceptDecision) {
        try {
            onDecision(decision)
        } catch (e: Exception) {
            // Callers handle their own errors; never let one break the stream's queue.
            System.err.println("Expedition intercept: decision callback failed: ${e.message}")
        }
    }
}
