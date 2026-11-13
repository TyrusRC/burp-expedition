package expedition.rules

import expedition.registry.ConnectionRegistry
import expedition.server.Json

/**
 * `/rules` routes of the control API (plugged into [expedition.server.ControlApiServer]):
 *
 * - `GET /rules` — list (with hit counts) · `DELETE /rules` — clear all
 * - `POST /rules` — add (body: rule JSON, optional `"index"`) · `GET|PUT|DELETE /rules/{id}`
 * - `POST /rules/{id}/enable` `{"enabled":bool}` · `POST /rules/{id}/move` `{"to":index}`
 * - `POST /rules/reorder` `{"ids":[...]}` · `POST /rules/webhooks` `{"enabled":bool}`
 * - `POST /rules/from-message` `{"connection_id":n, "message_id"?:n, "index"?:n, "add"?:true}`
 *
 * Returns (status, JSON). Bad input throws IllegalArgumentException (mapped to 400 by the server).
 */
class RulesApi(private val engine: RulesEngine, private val registry: ConnectionRegistry) {

    private fun ruleJson(r: HttpRule): Map<String, Any?> = RuleCodec.toMap(r) + ("hits" to engine.hitCount(r.id))

    private fun ok(vararg pairs: Pair<String, Any?>) = 200 to Json.obj(*pairs)
    private fun notFound(what: String) = 404 to Json.obj("error" to "$what not found")

    private fun bodyObj(body: String): Map<String, Any?> =
        if (body.isBlank()) emptyMap() else Json.asObject(Json.parse(body).also {
            require(it is Map<*, *>) { "body must be a JSON object" }
        })

    fun handle(method: String, path: String, body: String): Pair<Int, String> {
        val parts = path.trim('/').split('/')  // ["rules", ...]
        val id = parts.getOrNull(1)?.toLongOrNull()
        return when {
            parts.size == 1 && method == "GET" -> ok("webhooksEnabled" to engine.webhooksEnabled, "rules" to engine.rules().map(::ruleJson))
            parts.size == 1 && method == "POST" -> {
                val o = bodyObj(body)
                val r = engine.add(RuleCodec.fromMap(o).copy(id = 0), (o["index"] as? Number)?.toInt())
                ok("ok" to true, "rule" to ruleJson(r))
            }
            parts.size == 1 && method == "DELETE" -> { engine.clear(); ok("ok" to true) }
            parts.size == 2 && parts[1] == "reorder" && method == "POST" -> {
                val ids = (bodyObj(body)["ids"] as? List<*>)?.map { (it as? Number)?.toLong() ?: throw IllegalArgumentException("ids must be numbers") }
                    ?: throw IllegalArgumentException("'ids' required")
                engine.reorder(ids)
                ok("ok" to true, "order" to engine.rules().map { it.id })
            }
            parts.size == 2 && parts[1] == "webhooks" && method == "POST" -> {
                engine.webhooksEnabled = bodyObj(body)["enabled"] == true
                ok("ok" to true, "webhooksEnabled" to engine.webhooksEnabled)
            }
            parts.size == 2 && parts[1] == "from-message" && method == "POST" -> fromMessage(bodyObj(body))
            parts.size == 2 && id != null && method == "GET" -> engine.get(id)?.let { ok("rule" to ruleJson(it)) } ?: notFound("rule $id")
            parts.size == 2 && id != null && method == "PUT" -> {
                val r = engine.update(id, RuleCodec.fromMap(bodyObj(body))) ?: return notFound("rule $id")
                ok("ok" to true, "rule" to ruleJson(r))
            }
            parts.size == 2 && id != null && method == "DELETE" -> if (engine.remove(id)) ok("ok" to true) else notFound("rule $id")
            parts.size == 3 && id != null && parts[2] == "enable" && method == "POST" -> {
                if (engine.setEnabled(id, bodyObj(body)["enabled"] != false)) ok("ok" to true) else notFound("rule $id")
            }
            parts.size == 3 && id != null && parts[2] == "move" && method == "POST" -> {
                val to = (bodyObj(body)["to"] as? Number)?.toInt() ?: throw IllegalArgumentException("'to' required")
                if (engine.moveTo(id, to)) ok("ok" to true, "order" to engine.rules().map { it.id }) else notFound("rule $id")
            }
            else -> 404 to Json.obj("error" to "no route: $method $path")
        }
    }

    private fun fromMessage(o: Map<String, Any?>): Pair<Int, String> {
        val conn = (o["connection_id"] as? Number)?.toLong() ?: throw IllegalArgumentException("connection_id required")
        val messages = registry.messagesFor(conn)
        if (messages.isEmpty()) return notFound("connection $conn (or its messages)")
        val rule = RuleFromTraffic.fromConnection(
            messages, conn,
            messageId = (o["message_id"] as? Number)?.toLong(),
            index = (o["index"] as? Number)?.toInt(),
        )
        return if (o["add"] == false) ok("ok" to true, "rule" to RuleCodec.toMap(rule))
        else ok("ok" to true, "rule" to ruleJson(engine.add(rule)))
    }
}
