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
) {
    /** Pipeline/rule notes (REPLACED, TIMEOUT, UNSENT, DROPPED...) are the only messages carrying a dissectedView; they are not wire traffic. */
    val isNote: Boolean get() = dissectedView != null
}

data class ConnectionSummary(
    val connectionId: Long,
    val listenerName: String,
    val protocol: Protocol,
    val clientAddress: String,
    val upstreamAddress: String,
    val openedAt: Instant,
    val closedAt: Instant? = null,
    /** True when the connection is known to be TLS (set via ConnectionRegistry.markTls); false = unknown. */
    val tls: Boolean = false
)
