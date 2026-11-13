package expedition.rules

import expedition.server.Json

/**
 * Map/JSON form of [HttpRule], shared by persistence ([expedition.session.ConfigCodec]), the
 * control API and the UI editor. Example:
 * ```
 * {"name":"mock login","enabled":true,"times":null,
 *  "match":{"direction":"request","method":"POST","host":"*.example.com","path":"/login",
 *           "headers":[{"name":"X-Debug","value":"1"}],"bodyRegex":"user=admin"},
 *  "actions":[{"type":"delay","ms":200},
 *             {"type":"mock","status":200,"headers":[["Content-Type","application/json"]],"body":"{}"}]}
 * ```
 * Action types: mock, transformRequest, transformResponse, redirect, delay, timeout, close,
 * reset, passthrough, breakpoint, webhook. Bodies: `body` (text), `bodyHex`, or `bodyFile`.
 */
object RuleCodec {

    fun toMap(r: HttpRule): Map<String, Any?> = linkedMapOf(
        "id" to r.id, "name" to r.name, "enabled" to r.enabled, "times" to r.times,
        "match" to matcherMap(r.matcher),
        "actions" to r.actions.map(::actionMap),
    )

    fun toJson(r: HttpRule): String = Json.obj(toMap(r))

    private fun matcherMap(m: RuleMatcher): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>("direction" to m.direction.name.lowercase())
        m.method?.let { o["method"] = it }
        m.host?.let { o["host"] = it }
        m.port?.let { o["port"] = it }
        m.path?.let { o["path"] = it }
        m.pathRegex?.let { o["pathRegex"] = it }
        if (m.headers.isNotEmpty()) o["headers"] = m.headers.map { mapOf("name" to it.name, "value" to it.valueRegex) }
        m.bodyRegex?.let { o["bodyRegex"] = it }
        m.status?.let { o["status"] = it }
        m.listener?.let { o["listener"] = it }
        m.connectionId?.let { o["connectionId"] = it }
        return o
    }

    private fun bodyInto(o: MutableMap<String, Any?>, b: BodySource?) {
        when (b) {
            is BodySource.Text -> o["body"] = b.text
            is BodySource.Hex -> o["bodyHex"] = b.hex
            is BodySource.FromFile -> o["bodyFile"] = b.path
            null -> {}
        }
    }

    private fun pairs(p: List<Pair<String, String>>) = p.map { listOf(it.first, it.second) }

    private fun transformInto(o: MutableMap<String, Any?>, t: Transform) {
        if (t.setHeaders.isNotEmpty()) o["setHeaders"] = pairs(t.setHeaders)
        if (t.removeHeaders.isNotEmpty()) o["removeHeaders"] = t.removeHeaders
        bodyInto(o, t.replaceBody)
        if (t.bodyReplace.isNotEmpty()) o["replace"] = t.bodyReplace.map { mapOf("regex" to it.first, "with" to it.second) }
        t.urlReplace?.let { o["urlReplace"] = mapOf("regex" to it.first, "with" to it.second) }
        t.status?.let { o["status"] = it }
    }

    fun actionMap(a: RuleAction): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>()
        when (a) {
            is RuleAction.MockResponse -> {
                o["type"] = "mock"; o["status"] = a.status; a.reason?.let { o["reason"] = it }
                o["headers"] = pairs(a.headers); bodyInto(o, a.body)
            }
            is RuleAction.TransformRequest -> { o["type"] = "transformRequest"; transformInto(o, a.transform) }
            is RuleAction.TransformResponse -> { o["type"] = "transformResponse"; transformInto(o, a.transform) }
            is RuleAction.Redirect -> {
                o["type"] = "redirect"; o["url"] = a.url; o["keepHost"] = a.keepHost
                if (a.forwardCredentials) o["forwardCredentials"] = true
                if (a.insecureTls) o["insecureTls"] = true
            }
            is RuleAction.Delay -> { o["type"] = "delay"; o["ms"] = a.ms; o["jitterMs"] = a.jitterMs }
            RuleAction.Timeout -> o["type"] = "timeout"
            RuleAction.Close -> o["type"] = "close"
            RuleAction.Reset -> o["type"] = "reset"
            RuleAction.PassThrough -> o["type"] = "passthrough"
            is RuleAction.Breakpoint -> { o["type"] = "breakpoint"; o["request"] = a.request; o["response"] = a.response }
            is RuleAction.Webhook -> {
                o["type"] = "webhook"; o["url"] = a.url; o["respond"] = a.respond
                if (a.allowLocal) o["allowLocal"] = true
                if (a.forwardCredentials) o["forwardCredentials"] = true
                if (a.insecureTls) o["insecureTls"] = true
            }
        }
        return o
    }

    // ── decoding ──────────────────────────────────────────────────────────

    fun fromJson(text: String): HttpRule = fromMap(Json.asObject(Json.parse(text)))

    /** Decodes and validates; throws IllegalArgumentException on bad input. */
    fun fromMap(o: Map<String, Any?>): HttpRule {
        val match = Json.asObject(o["match"])
        val actions = (o["actions"] as? List<*>)?.map { actionFromMap(Json.asObject(it)) }
            ?: throw IllegalArgumentException("'actions' must be a list")
        val rule = HttpRule(
            id = num(o["id"])?.toLong() ?: 0,
            name = (o["name"] as? String) ?: "",
            enabled = o["enabled"] != false,
            matcher = matcherFromMap(match),
            actions = actions.ifEmpty { listOf(RuleAction.PassThrough) },
            times = num(o["times"])?.toInt(),
        )
        try { rule.validate() } catch (e: IllegalArgumentException) { throw e } catch (e: Exception) {
            throw IllegalArgumentException("invalid rule: ${e.message}")
        }
        return rule
    }

    private fun num(v: Any?): Number? = when (v) {
        is Number -> v
        is String -> v.trim().toDoubleOrNull()
        else -> null
    }

    private fun s(o: Map<String, Any?>, k: String): String? = (o[k] as? String)?.takeIf { it.isNotEmpty() }

    fun matcherFromMap(m: Map<String, Any?>): RuleMatcher = RuleMatcher(
        direction = when (s(m, "direction")?.lowercase()) {
            null, "request" -> RuleDirection.REQUEST
            "response" -> RuleDirection.RESPONSE
            else -> throw IllegalArgumentException("direction must be request|response")
        },
        method = s(m, "method"),
        host = s(m, "host"),
        port = num(m["port"])?.toInt(),
        path = s(m, "path"),
        pathRegex = s(m, "pathRegex"),
        headers = (m["headers"] as? List<*>)?.map { h ->
            val ho = Json.asObject(h)
            HeaderMatch(s(ho, "name") ?: throw IllegalArgumentException("header matcher needs 'name'"), s(ho, "value"))
        } ?: emptyList(),
        bodyRegex = s(m, "bodyRegex"),
        status = num(m["status"])?.toInt(),
        listener = s(m, "listener"),
        connectionId = num(m["connectionId"])?.toLong(),
    )

    /** Headers as `[[name,value],...]` or `{"name":"value"}`. */
    fun headerPairs(v: Any?): List<Pair<String, String>> = when (v) {
        null -> emptyList()
        is Map<*, *> -> v.entries.map { it.key.toString() to (it.value?.toString() ?: "") }
        is List<*> -> v.map { e ->
            when (e) {
                is List<*> -> { require(e.size == 2) { "header pair must be [name, value]" }; e[0].toString() to e[1].toString() }
                is Map<*, *> -> (e["name"]?.toString() ?: throw IllegalArgumentException("header needs name")) to (e["value"]?.toString() ?: "")
                is String -> { val i = e.indexOf(':'); require(i > 0) { "header must be 'Name: value'" }; e.substring(0, i).trim() to e.substring(i + 1).trim() }
                else -> throw IllegalArgumentException("bad header entry")
            }
        }
        else -> throw IllegalArgumentException("headers must be a list or object")
    }

    private fun bodyFrom(o: Map<String, Any?>): BodySource? = when {
        o["bodyHex"] is String -> BodySource.Hex(o["bodyHex"] as String)
        o["bodyFile"] is String -> BodySource.FromFile.load(o["bodyFile"] as String)
        o["body"] is String -> BodySource.Text(o["body"] as String)
        else -> null
    }

    private fun transformFrom(o: Map<String, Any?>): Transform = Transform(
        setHeaders = headerPairs(o["setHeaders"]),
        removeHeaders = (o["removeHeaders"] as? List<*>)?.map { it.toString() } ?: emptyList(),
        replaceBody = bodyFrom(o),
        bodyReplace = (o["replace"] as? List<*>)?.map { r ->
            val ro = Json.asObject(r)
            (s(ro, "regex") ?: throw IllegalArgumentException("replace needs 'regex'")) to ((ro["with"] as? String) ?: "")
        } ?: emptyList(),
        urlReplace = (o["urlReplace"] as? Map<*, *>)?.let { u ->
            val uo = Json.asObject(u)
            (s(uo, "regex") ?: throw IllegalArgumentException("urlReplace needs 'regex'")) to ((uo["with"] as? String) ?: "")
        },
        status = num(o["status"])?.toInt(),
    )

    fun actionFromMap(o: Map<String, Any?>): RuleAction = when (val t = (o["type"] as? String)?.lowercase()) {
        "mock", "mockresponse", "fixed" -> RuleAction.MockResponse(
            status = num(o["status"])?.toInt() ?: 200,
            reason = o["reason"] as? String,
            headers = headerPairs(o["headers"]),
            body = bodyFrom(o) ?: BodySource.Text(""),
        ).also { require(it.status in 100..999) { "status must be 100-999" } }
        "transformrequest" -> RuleAction.TransformRequest(transformFrom(o))
        "transformresponse" -> RuleAction.TransformResponse(transformFrom(o))
        "redirect", "forward" -> RuleAction.Redirect(s(o, "url") ?: throw IllegalArgumentException("redirect needs 'url'"), o["keepHost"] == true,
            forwardCredentials = o["forwardCredentials"] == true, insecureTls = o["insecureTls"] == true)
        "delay" -> RuleAction.Delay(num(o["ms"])?.toLong() ?: 0, num(o["jitterMs"])?.toLong() ?: 0)
        "timeout" -> RuleAction.Timeout
        "close" -> RuleAction.Close
        "reset" -> RuleAction.Reset
        "passthrough" -> RuleAction.PassThrough
        "breakpoint" -> RuleAction.Breakpoint(o["request"] != false, o["response"] == true)
        "webhook", "callback" -> RuleAction.Webhook(s(o, "url") ?: throw IllegalArgumentException("webhook needs 'url'"), o["respond"] == true,
            allowLocal = o["allowLocal"] == true, forwardCredentials = o["forwardCredentials"] == true, insecureTls = o["insecureTls"] == true)
        else -> throw IllegalArgumentException("unknown action type '$t'")
    }
}
