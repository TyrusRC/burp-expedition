package expedition.registry

import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

class ConnectionRegistry {
    private val connections = LinkedHashMap<Long, ConnectionSummary>()
    private val messages = mutableListOf<ProxyMessage>()
    private val nextConnectionId = AtomicLong(1)
    private val nextMessageId = AtomicLong(1)

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
        messages.add(message)
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
}
