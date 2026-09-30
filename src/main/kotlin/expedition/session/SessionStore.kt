package expedition.session

import expedition.registry.ConnectionSummary
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.registry.ProxyMessage
import expedition.server.Json
import java.time.Instant
import java.util.Base64

/** A saved proxy session: connections, their messages, and flow tags. */
data class SessionSnapshot(
    val connections: List<ConnectionSummary>,
    val messages: List<ProxyMessage>,
    val tags: Map<Long, Set<String>>
)

/**
 * Serialises a [SessionSnapshot] to/from JSON so a testing session can be saved to a file
 * and reloaded later (or exported as evidence). Raw bytes are Base64-encoded; timestamps are
 * epoch milliseconds. Reuses the extension's zero-dependency [Json] to avoid a JSON library.
 */
object SessionStore {

    fun export(snapshot: SessionSnapshot): String {
        val conns = snapshot.connections.map {
            mapOf<String, Any?>(
                "connectionId" to it.connectionId, "listenerName" to it.listenerName,
                "protocol" to it.protocol.name, "clientAddress" to it.clientAddress,
                "upstreamAddress" to it.upstreamAddress, "openedAt" to it.openedAt.toEpochMilli(),
                "closedAt" to it.closedAt?.toEpochMilli()
            )
        }
        val msgs = snapshot.messages.map {
            mapOf<String, Any?>(
                "id" to it.id, "connectionId" to it.connectionId, "direction" to it.direction.name,
                "timestamp" to it.timestamp.toEpochMilli(),
                "rawBytes" to Base64.getEncoder().encodeToString(it.rawBytes),
                "dissectedView" to it.dissectedView
            )
        }
        val tags = snapshot.tags.entries.associate { it.key.toString() to it.value.toList() }
        return Json.obj("connections" to conns, "messages" to msgs, "tags" to tags)
    }

    @Suppress("UNCHECKED_CAST")
    fun import(json: String): SessionSnapshot {
        val root = Json.asObject(Json.parse(json))
        val connections = (root["connections"] as? List<Any?> ?: emptyList()).map {
            val o = Json.asObject(it)
            ConnectionSummary(
                long(o, "connectionId"), Json.str(o, "listenerName"),
                Protocol.valueOf(Json.str(o, "protocol")), Json.str(o, "clientAddress"),
                Json.str(o, "upstreamAddress"), Instant.ofEpochMilli(long(o, "openedAt")),
                (o["closedAt"] as? Number)?.let { n -> Instant.ofEpochMilli(n.toLong()) }
            )
        }
        val messages = (root["messages"] as? List<Any?> ?: emptyList()).map {
            val o = Json.asObject(it)
            ProxyMessage(
                long(o, "id"), long(o, "connectionId"), Direction.valueOf(Json.str(o, "direction")),
                Instant.ofEpochMilli(long(o, "timestamp")),
                Base64.getDecoder().decode(Json.str(o, "rawBytes")),
                (o["dissectedView"] as? String)
            )
        }
        val tags = Json.asObject(root["tags"]).entries.associate { (k, v) ->
            k.toLong() to ((v as? List<Any?> ?: emptyList()).map { it.toString() }.toSet())
        }
        return SessionSnapshot(connections, messages, tags)
    }

    private fun long(o: Map<String, Any?>, key: String): Long = when (val x = o[key]) {
        is Number -> x.toLong()
        is String -> x.toLongOrNull() ?: 0L
        else -> 0L
    }
}
