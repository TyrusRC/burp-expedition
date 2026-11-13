package expedition.registry

import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * In-memory capture log. History is bounded to [maxMessages] (a ring buffer, oldest
 * evicted first): each message holds the full rawBytes, so an unbounded log on a
 * long-running MITM would exhaust Burp's heap. The default is large enough for normal
 * engagements; pass a smaller value under memory pressure.
 */
class ConnectionRegistry(
    private val maxMessages: Int = DEFAULT_MAX_MESSAGES,
    /** Total rawBytes budget across retained messages; the oldest are evicted first. */
    private val maxBytes: Long = DEFAULT_MAX_BYTES,
    /** How many CLOSED connections to retain; the least recently closed are dropped first. */
    private val maxClosedConnections: Int = DEFAULT_MAX_CLOSED_CONNECTIONS,
    /** Cap on simultaneously OPEN live connections accepted via [tryOpenConnection]. */
    private val maxOpenConnections: Int = DEFAULT_MAX_OPEN_CONNECTIONS,
) {
    private var openCount = 0
    private val connections = LinkedHashMap<Long, ConnectionSummary>()
    private val closedOrder = ArrayDeque<Long>()
    private val messages = ArrayDeque<ProxyMessage>()
    private var retainedBytes = 0L
    private val nextConnectionId = AtomicLong(1)
    private val nextMessageId = AtomicLong(1)

    init {
        require(maxMessages > 0) { "maxMessages must be positive" }
        require(maxBytes > 0) { "maxBytes must be positive" }
        require(maxClosedConnections >= 0) { "maxClosedConnections must be non-negative" }
        require(maxOpenConnections > 0) { "maxOpenConnections must be positive" }
    }

    @Synchronized
    fun openConnection(listenerName: String, protocol: Protocol, clientAddress: String, upstreamAddress: String): Long {
        val id = nextConnectionId.getAndIncrement()
        connections[id] = ConnectionSummary(id, listenerName, protocol, clientAddress, upstreamAddress, Instant.now())
        openCount++
        return id
    }

    /**
     * Like [openConnection] but returns null (opening nothing) when [maxOpenConnections] live
     * connections are already open — listeners then refuse the new client instead of letting a
     * connection flood exhaust file descriptors / heap.
     */
    @Synchronized
    fun tryOpenConnection(listenerName: String, protocol: Protocol, clientAddress: String, upstreamAddress: String): Long? =
        if (openCount >= maxOpenConnections) null
        else openConnection(listenerName, protocol, clientAddress, upstreamAddress)

    @Synchronized
    fun markTls(connectionId: Long) {
        val c = connections[connectionId] ?: return
        connections[connectionId] = c.copy(tls = true)
    }

    @Synchronized
    fun openConnectionCount(): Int = openCount

    @Synchronized
    fun closeConnection(connectionId: Long) {
        val existing = connections[connectionId] ?: return
        if (existing.closedAt == null) {
            closedOrder.addLast(connectionId)
            if (openCount > 0) openCount--
        }
        connections[connectionId] = existing.copy(closedAt = Instant.now())
        // Retain only the newest [maxClosedConnections] closed connections; open ones are never dropped here.
        while (closedOrder.size > maxClosedConnections) connections.remove(closedOrder.removeFirst())
    }

    @Synchronized
    fun recordMessage(connectionId: Long, direction: Direction, rawBytes: ByteArray, dissectedView: String? = null): ProxyMessage {
        val message = ProxyMessage(nextMessageId.getAndIncrement(), connectionId, direction, Instant.now(), rawBytes, dissectedView)
        messages.addLast(message)
        retainedBytes += rawBytes.size
        // Evict by count, then by byte budget. The newest message is always kept, even if it alone exceeds the budget.
        evict()
        return message
    }

    private fun evict() {
        while (messages.size > maxMessages || (retainedBytes > maxBytes && messages.size > 1)) {
            retainedBytes = maxOf(0L, retainedBytes - messages.removeFirst().rawBytes.size)
        }
    }

    /** Total bytes currently held by retained messages (for diagnostics and tests). */
    @Synchronized
    fun retainedMessageBytes(): Long = retainedBytes

    /** Outcome of [importSnapshot]. [connectionIdMap] maps snapshot id -> id used in this registry. */
    data class ImportResult(
        val connectionsAdded: Int,
        val messagesAdded: Int,
        val skippedDuplicates: Int,
        val connectionIdMap: Map<Long, Long>,
    )

    /**
     * Restores a saved session into this registry, preserving ids, directions, timestamps and
     * bytes. Idempotent: an entry whose id already exists with identical content is skipped, so
     * loading the same file twice adds nothing. If an id exists with DIFFERENT content (e.g. live
     * traffic captured since), the incoming entry is re-keyed to a fresh id rather than
     * overwriting; [ImportResult.connectionIdMap] reports the mapping so callers can remap tags.
     * Messages whose connection is unknown are dropped. The id counters are advanced past
     * everything imported so later live traffic never collides.
     */
    fun importSnapshot(importedConnections: List<ConnectionSummary>, importedMessages: List<ProxyMessage>): ImportResult {
        // Phase 1 (short lock): capture what exists now.
        val snapConns: List<ConnectionSummary>
        val snapMsgs: List<ProxyMessage>
        synchronized(this) { snapConns = connections.values.toList(); snapMsgs = messages.toList() }
        // Phase 2 (NO lock): the heavy hashing. Live traffic keeps flowing meanwhile.
        val snapConnIds = HashSet<Long>(snapConns.size * 2).also { s -> snapConns.forEach { s.add(it.connectionId) } }
        val twinIndex = HashMap<ConnectionSummary, Long>(snapConns.size * 2)
        snapConns.forEach { twinIndex.putIfAbsent(it.copy(connectionId = 0L), it.connectionId) }
        val snapMsgIds = HashSet<Long>(snapMsgs.size * 2)
        val contentKeys = HashSet<MsgKey>(snapMsgs.size * 2)
        snapMsgs.forEach { snapMsgIds.add(it.id); contentKeys.add(MsgKey(it)) }
        val importedHashes = IntArray(importedMessages.size) { importedMessages[it].rawBytes.contentHashCode() }
        // Phase 3 (lock): re-check against anything that arrived since the snapshot, then insert.
        synchronized(this) {
            for (c in connections.values) if (c.connectionId !in snapConnIds) twinIndex.putIfAbsent(c.copy(connectionId = 0L), c.connectionId)
            val byId = HashMap<Long, ProxyMessage>(messages.size * 2)
            for (m in messages) {
                byId[m.id] = m
                if (m.id !in snapMsgIds) contentKeys.add(MsgKey(m))
            }
            val idMap = HashMap<Long, Long>()
            var connsAdded = 0
            var msgsAdded = 0
            var skipped = 0
            for (c in importedConnections) {
                val existing = connections[c.connectionId]
                when {
                    existing == null -> {
                        connections[c.connectionId] = c
                        twinIndex.putIfAbsent(c.copy(connectionId = 0L), c.connectionId)
                        idMap[c.connectionId] = c.connectionId
                        connsAdded++
                    }
                    existing == c -> { idMap[c.connectionId] = c.connectionId; skipped++ }
                    else -> {
                        // Same content already re-keyed by an earlier import? Then reuse it.
                        val twinId = twinIndex[c.copy(connectionId = 0L)]
                        if (twinId != null) { idMap[c.connectionId] = twinId; skipped++; continue }
                        val fresh = nextConnectionId.getAndIncrement()
                        connections[fresh] = c.copy(connectionId = fresh)
                        twinIndex.putIfAbsent(c.copy(connectionId = 0L), fresh)
                        idMap[c.connectionId] = fresh
                        connsAdded++
                    }
                }
            }
            for ((i, m) in importedMessages.withIndex()) {
                val connId = idMap[m.connectionId] ?: continue
                val incoming = if (connId == m.connectionId) m else m.copy(connectionId = connId)
                val existing = byId[m.id]
                if (existing != null && MsgKey(incoming, importedHashes[i]) in contentKeys) { skipped++; continue }
                val stored = if (existing == null) incoming else incoming.copy(id = nextMessageId.getAndIncrement())
                messages.addLast(stored)
                retainedBytes += stored.rawBytes.size
                byId[stored.id] = stored
                contentKeys.add(MsgKey(stored, importedHashes[i]))
                msgsAdded++
            }
            evict()
            bump(nextConnectionId, connections.keys.maxOrNull())
            bump(nextMessageId, byId.keys.maxOrNull())
            return ImportResult(connsAdded, msgsAdded, skipped, idMap)
        }
    }

    /** Content identity of a message (ignores its id); equality compares the bytes by value. */
    private class MsgKey(m: ProxyMessage, bytesHash: Int = m.rawBytes.contentHashCode()) {
        private val connectionId = m.connectionId
        private val direction = m.direction
        private val timestamp = m.timestamp
        private val bytes = m.rawBytes
        private val view = m.dissectedView
        private val hash = ((((connectionId.hashCode() * 31 + direction.hashCode()) * 31 + timestamp.hashCode()) * 31) +
            bytesHash) * 31 + (view?.hashCode() ?: 0)
        override fun hashCode() = hash
        override fun equals(other: Any?) = other is MsgKey && hash == other.hash && connectionId == other.connectionId &&
            direction == other.direction && timestamp == other.timestamp && bytes.contentEquals(other.bytes) && view == other.view
    }

    private fun bump(counter: AtomicLong, maxSeen: Long?) {
        if (maxSeen != null) counter.updateAndGet { maxOf(it, maxSeen + 1) }
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
        // typical Burp heap, while still capping a runaway capture. The byte budget
        // (DEFAULT_MAX_BYTES) is the real memory bound; this count cap applies on top of it.
        const val DEFAULT_MAX_MESSAGES = 50_000

        /** 256 MiB of retained message payload; the count cap alone does not bound memory. */
        const val DEFAULT_MAX_BYTES = 256L * 1024 * 1024

        /** Closed connections kept for history; open connections are not capped. */
        const val DEFAULT_MAX_CLOSED_CONNECTIONS = 10_000
        const val DEFAULT_MAX_OPEN_CONNECTIONS = 10_000
    }
}
