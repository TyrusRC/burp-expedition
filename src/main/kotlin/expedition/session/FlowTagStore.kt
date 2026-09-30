package expedition.session

import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe map of connection id → user tags, kept separate from [expedition.registry.ConnectionRegistry]
 * so tagging doesn't touch the relay's hot path. Written from the Swing EDT, read anywhere.
 */
class FlowTagStore {
    private val tags = ConcurrentHashMap<Long, MutableSet<String>>()

    fun tag(connectionId: Long, tag: String) {
        tags.computeIfAbsent(connectionId) { ConcurrentHashMap.newKeySet() }.add(tag)
    }

    fun untag(connectionId: Long, tag: String) {
        tags[connectionId]?.remove(tag)
    }

    fun tags(connectionId: Long): Set<String> = tags[connectionId]?.toSet() ?: emptySet()

    fun taggedWith(tag: String): List<Long> = tags.filterValues { it.contains(tag) }.keys.sorted()

    fun all(): Map<Long, Set<String>> = tags.mapValues { it.value.toSet() }

    fun load(entries: Map<Long, Set<String>>) {
        entries.forEach { (id, ts) -> ts.forEach { tag(id, it) } }
    }
}
