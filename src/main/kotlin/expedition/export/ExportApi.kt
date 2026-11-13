package expedition.export

import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.server.Json
import java.io.ByteArrayOutputStream

/** Control-API handlers for HAR / code-snippet export. Each returns a JSON body; IllegalArgumentException maps to HTTP 400. */
object ExportApi {
    /** GET /export/har[?connection=ID]. The HAR document itself is the response body. */
    fun exportHar(registry: ConnectionRegistry, connection: String?): String {
        val id = connection?.let { it.toLongOrNull() ?: throw IllegalArgumentException("connection must be a number") }
        return HarCodec.export(registry, id).json
    }

    /** POST /import/har with a HAR document as body. */
    fun importHar(registry: ConnectionRegistry, body: String): String {
        val r = HarCodec.import(registry, body)
        return Json.obj("entries" to r.entries, "connectionsAdded" to r.connectionsAdded,
            "messagesAdded" to r.messagesAdded, "skippedEntries" to r.skippedEntries)
    }

    fun targets(): String = Json.obj("targets" to SnippetRegistry.all.map {
        mapOf("id" to it.id, "label" to it.label, "language" to it.language)
    })

    /** GET /export/snippet?connection=&message=&target= ; lists the targets when [target] is missing. */
    fun snippet(registry: ConnectionRegistry, connection: String?, message: String?, target: String?): String {
        if (target.isNullOrBlank()) return targets()
        val gen = SnippetRegistry.get(target) ?: throw IllegalArgumentException("unknown target '$target'; GET /export/snippet lists targets")
        val connId = connection?.toLongOrNull() ?: throw IllegalArgumentException("connection is required")
        val conn = registry.connection(connId) ?: throw IllegalArgumentException("unknown connection $connId")
        val msgs = registry.messagesFor(connId)
        val raw: ByteArray = if (message != null) {
            val mid = message.toLongOrNull() ?: throw IllegalArgumentException("message must be a number")
            (msgs.firstOrNull { it.id == mid } ?: throw IllegalArgumentException("unknown message $mid in connection $connId")).rawBytes
        } else {
            val o = ByteArrayOutputStream()
            msgs.filter { it.direction == Direction.CLIENT_TO_UPSTREAM && !it.isNote }.forEach { o.write(it.rawBytes) }
            o.toByteArray()
        }
        val code = gen.generate(SnippetRequest.fromRaw(raw, conn.upstreamAddress, conn.tls))
        return Json.obj("target" to gen.id, "language" to gen.language, "code" to code)
    }
}
