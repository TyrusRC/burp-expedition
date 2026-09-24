package expedition.registry

import java.time.Instant

enum class Protocol { TCP, UDP }

enum class Direction { CLIENT_TO_UPSTREAM, UPSTREAM_TO_CLIENT }

data class ProxyMessage(
    val id: Long,
    val connectionId: Long,
    val direction: Direction,
    val timestamp: Instant,
    val rawBytes: ByteArray,
    val dissectedView: String? = null
)

data class ConnectionSummary(
    val connectionId: Long,
    val listenerName: String,
    val protocol: Protocol,
    val clientAddress: String,
    val upstreamAddress: String,
    val openedAt: Instant,
    val closedAt: Instant? = null
)
