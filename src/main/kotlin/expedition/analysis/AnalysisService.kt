package expedition.analysis

import expedition.registry.ConnectionRegistry

/** Runs compression, cache and (when a spec is loaded) OpenAPI analyzers over captured HTTP/1.x traffic. */
object AnalysisService {
    @Volatile var spec: OpenApiSpec? = null
        private set

    fun loadOpenApi(text: String): OpenApiSpec = OpenApiSpec.parse(text).also { spec = it }
    fun clearOpenApi() { spec = null }

    fun analyze(x: HttpExchange, spec: OpenApiSpec? = this.spec): List<Finding> {
        val out = ArrayList<Finding>()
        out += CompressionAnalyzer.analyze(x)
        out += CacheAnalyzer.analyze(x)
        if (spec != null) out += spec.validate(x)
        return out
    }

    /** Findings for one connection, or all connections when [connectionId] is null. */
    fun report(registry: ConnectionRegistry, connectionId: Long? = null): List<Finding> {
        val ids = connectionId?.let { listOf(it) } ?: registry.allConnections().map { it.connectionId }
        val s = spec
        return ids.flatMap { id ->
            HttpExchanges.extract(id, registry.messagesFor(id)).flatMap { analyze(it, s) }
        }
    }
}
