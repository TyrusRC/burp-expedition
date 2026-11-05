package expedition.registry

import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * In-memory capture log. History is bounded to [maxMessages] (a ring buffer, oldest
 * evicted first): each message holds the full rawBytes, so an unbounded log on a
 * long-running MITM would exhaust Burp's heap. The default is large enough for normal
 * engagements; pass a smaller value under memory pressure.
 */
class ConnectionRegistry(private val maxMessages: Int = DEFAULT_MAX_MESSAGES) {
    private val connections = LinkedHashMap<Long, ConnectionSummary>()
    private val messages = ArrayDeque<ProxyMessage>()
    private val nextConnectionId = AtomicLong(1)
    private val nextMessageId = AtomicLong(1)

    init {
        require(maxMessages > 0) { "maxMessages must be positive" }
    }

    @Synchronized
    fun openConnection(listenerName: String, protocol: Protocol, clientAddress: String, upstreamAddress: String): Long {
        val id = nextConnectionId.getAndIncrement()
        connections[id] = ConnectionSummary(id, listenerName, protocol, clientAddress, upstreamAddress, Instant.now())
        return id
    }

    @Synchronized
    fun closeConnection(connectionId: Long) {
        val existing = connections[connectionId] ?: return
        connections[connectionId] = existing.copy(closedAt = Instant.now())
    }

    @Synchronized
    fun recordMessage(connectionId: Long, direction: Direction, rawBytes: ByteArray, dissectedView: String? = null): ProxyMessage {
        val message = ProxyMessage(nextMessageId.getAndIncrement(), connectionId, direction, Instant.now(), rawBytes, dissectedView)
        messages.addLast(message)
        while (messages.size > maxMessages) messages.removeFirst()
        return message
    }

    @Synchronized
    fun messagesFor(connectionId: Long): List<ProxyMessage> = messages.filter { it.connectionId == connectionId }

    @Synchronized
    fun allMessages(): List<ProxyMessage> = messages.toList()

    @Synchronized
    fun allConnections(): List<ConnectionSummary> = connections.values.toList()

    @Synchronized
    fun connection(connectionId: Long): ConnectionSummary? = connections[connectionId]

    companion object {
        // ~50k messages; at a few KB each this is tens-to-hundreds of MB, well within a
        // typical Burp heap, while still capping a runaway capture. NOTE: a fixed count,
        // not a byte budget — a flood of very large messages could still be heavy.
        // Upgrade path: switch to a byte-size budget if that proves a problem.
        const val DEFAULT_MAX_MESSAGES = 50_000
    }
}
