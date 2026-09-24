package expedition.session

import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class UdpSessionTable<T>(
    private val idleTimeout: Duration,
    private val clock: () -> Instant = { Instant.now() }
) {
    private data class Session<T>(val value: T, var lastActivity: Instant)

    private val sessions = ConcurrentHashMap<InetSocketAddress, Session<T>>()

    fun sessionFor(clientAddress: InetSocketAddress, create: () -> T): T {
        val now = clock()
        val existing = sessions[clientAddress]
        if (existing != null) {
            existing.lastActivity = now
            return existing.value
        }
        val created = create()
        sessions[clientAddress] = Session(created, now)
        return created
    }

    fun evictIdle(onEvict: (InetSocketAddress, T) -> Unit) {
        val now = clock()
        val expiredKeys = sessions.entries
            .filter { Duration.between(it.value.lastActivity, now) > idleTimeout }
            .map { it.key }
        for (key in expiredKeys) {
            sessions.remove(key)?.let { onEvict(key, it.value) }
        }
    }

    fun drainAll(onEvict: (InetSocketAddress, T) -> Unit) {
        val keys = sessions.keys.toList()
        for (key in keys) {
            sessions.remove(key)?.let { onEvict(key, it.value) }
        }
    }

    fun size(): Int = sessions.size
}
