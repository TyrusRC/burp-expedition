package expedition.analysis

enum class Severity { INFO, WARNING, ERROR }

/** One analysis result tied to a request/response pair of a connection. */
data class Finding(
    val connectionId: Long,
    /** Short label of the exchange, e.g. `GET /api/users -> 200`. */
    val exchange: String,
    /** compression | cache | openapi */
    val category: String,
    val severity: Severity,
    val code: String,
    val message: String,
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "connection" to connectionId, "exchange" to exchange, "category" to category,
        "severity" to severity.name, "code" to code, "message" to message,
    )
}
