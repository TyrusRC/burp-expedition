package expedition.analysis

import expedition.server.Json
import java.net.URLDecoder

/**
 * OpenAPI 3.x conformance check of captured HTTP exchanges. Loads JSON or YAML (via [MiniYaml]),
 * resolves local `#/...` refs and validates path/method, parameters, request/response
 * content-types, response status and a basic JSON-Schema subset of bodies.
 */
class OpenApiSpec private constructor(private val root: Map<String, Any?>) {
    private class Route(val template: String, val regex: Regex, val names: List<String>, val literalLen: Int)

    private val paths: Map<String, Any?> = obj(root["paths"])
    private val routes: List<Route>
    private val basePaths: List<String>
    val title: String = obj(root["info"])["title"]?.toString() ?: ""
    val version: String = root["openapi"].toString()
    val operationCount: Int get() = paths.values.sumOf { p -> METHODS.count { obj(p).containsKey(it) } }

    init {
        routes = paths.keys.map { t ->
            val names = ArrayList<String>(); val sb = StringBuilder("^")
            var lit = 0; var i = 0
            while (i < t.length) {
                if (t[i] == '{') {
                    val e = t.indexOf('}', i).let { if (it < 0) t.length - 1 else it }
                    names.add(t.substring(i + 1, e)); sb.append("([^/]+)"); i = e + 1
                } else { sb.append(Regex.escape(t[i].toString())); lit++; i++ }
            }
            Route(t, Regex(sb.append("$").toString()), names, lit)
        }.sortedByDescending { it.literalLen }
        basePaths = list(root["servers"]).mapNotNull { s ->
            val u = obj(s)["url"]?.toString() ?: return@mapNotNull null
            val p = Regex("^(?:[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*)?(/.*)?$").find(u)?.groupValues?.get(1)?.trimEnd('/') ?: ""
            p
        }.distinct().filter { it.isNotEmpty() }
    }

    companion object {
        private val METHODS = listOf("get", "put", "post", "delete", "options", "head", "patch", "trace")
        private const val MAX_ERRORS = 10

        /** Parses a JSON or YAML OpenAPI 3.x document; throws IllegalArgumentException when invalid. */
        fun parse(text: String): OpenApiSpec {
            val t = text.trim()
            if (t.isEmpty()) throw IllegalArgumentException("empty OpenAPI document")
            val doc = try { if (t.startsWith("{")) Json.parse(t) else MiniYaml.parse(t) }
            catch (e: Exception) { throw IllegalArgumentException("cannot parse OpenAPI document: ${e.message}") }
            val m = doc as? Map<*, *> ?: throw IllegalArgumentException("OpenAPI document must be an object")
            @Suppress("UNCHECKED_CAST") val root = m as Map<String, Any?>
            val v = root["openapi"]?.toString() ?: throw IllegalArgumentException("missing 'openapi' version field (only OpenAPI 3.x is supported)")
            if (!v.startsWith("3.")) throw IllegalArgumentException("unsupported OpenAPI version '$v' (only 3.x)")
            if (root["paths"] !is Map<*, *>) throw IllegalArgumentException("missing 'paths' object")
            return OpenApiSpec(root)
        }

        @Suppress("UNCHECKED_CAST")
        private fun obj(v: Any?): Map<String, Any?> = (v as? Map<String, Any?>) ?: emptyMap()
        private fun list(v: Any?): List<Any?> = (v as? List<Any?>) ?: emptyList()
    }

    // ── $ref ──────────────────────────────────────────────────────────────
    private fun resolve(v: Any?): Map<String, Any?> {
        var cur = obj(v); var hops = 0
        while (cur["\$ref"] is String && hops++ < 16) {
            val ref = cur["\$ref"] as String
            if (!ref.startsWith("#/")) return emptyMap()
            var node: Any? = root
            for (seg in ref.substring(2).split('/')) node = obj(node)[seg.replace("~1", "/").replace("~0", "~")]
            cur = obj(node)
        }
        return cur
    }

    // ── exchange validation ───────────────────────────────────────────────
    fun validate(x: HttpExchange): List<Finding> {
        val out = ArrayList<Finding>()
        fun add(sev: Severity, code: String, msg: String) = out.add(Finding(x.connectionId, x.label, "openapi", sev, code, msg))
        val target = x.request.target
        val rawPath = target.substringBefore('?').substringBefore('#').let {
            if (it.contains("://")) "/" + it.substringAfter("://").substringAfter('/', "") else it
        }
        val rawQuery = if (target.contains('?')) target.substringAfter('?').substringBefore('#') else ""
        var path = rawPath
        for (b in basePaths) if (path == b || path.startsWith("$b/")) { path = path.removePrefix(b).ifEmpty { "/" }; break }
        val trimmed = if (path.length > 1) path.trimEnd('/') else path

        val route = routes.firstOrNull { it.regex.matches(trimmed) }
            ?: routes.firstOrNull { it.regex.matches(path) }
        if (route == null) {
            add(Severity.WARNING, "openapi.path-not-found", "Path $rawPath is not defined in the OpenAPI spec")
            return out
        }
        val pathItem = resolve(paths[route.template])
        val method = x.request.method.lowercase()
        val op = if (method in METHODS) resolve(pathItem[method]).takeIf { pathItem.containsKey(method) } else null
        if (op == null) {
            val allowed = METHODS.filter { pathItem.containsKey(it) }.joinToString(", ") { it.uppercase() }
            add(Severity.ERROR, "openapi.method-not-allowed", "Method ${x.request.method} is not defined for ${route.template} (spec allows: $allowed)")
            return out
        }

        // Parameters (operation overrides path-level by name+in).
        val params = LinkedHashMap<String, Map<String, Any?>>()
        for (p in list(pathItem["parameters"]) + list(op["parameters"])) {
            val r = resolve(p); params["${r["in"]}:${r["name"]}"] = r
        }
        val groups = route.regex.find(trimmed)?.groupValues?.drop(1) ?: emptyList()
        val pathVals = route.names.zip(groups).toMap()
        val query = parseQuery(rawQuery)
        val cookies = (x.request.header("cookie") ?: "").split(';').mapNotNull {
            val i = it.indexOf('='); if (i <= 0) null else it.substring(0, i).trim() to it.substring(i + 1).trim()
        }.toMap()
        for (p in params.values) {
            val name = p["name"]?.toString() ?: continue
            val required = p["required"] == true || p["in"] == "path"
            val value: String? = when (p["in"]) {
                "path" -> pathVals[name]?.let { decode(it) }
                "query" -> query[name]?.firstOrNull()
                "header" -> x.request.header(name)
                "cookie" -> cookies[name]
                else -> null
            }
            if (value == null) {
                if (required) add(Severity.ERROR, "openapi.missing-parameter", "Required ${p["in"]} parameter '$name' is missing")
                continue
            }
            val schema = resolve(p["schema"])
            if (schema.isNotEmpty()) {
                val err = checkScalar(value, schema)
                if (err != null) add(Severity.ERROR, "openapi.invalid-parameter", "${p["in"]} parameter '$name' = '$value': $err")
            }
        }

        // Request body.
        val rb = resolve(op["requestBody"])
        val reqCt = x.request.contentType
        val hasReqBody = x.request.body.isNotEmpty()
        if (rb.isNotEmpty()) {
            if (!hasReqBody) {
                if (rb["required"] == true) add(Severity.ERROR, "openapi.missing-body", "Request body is required but empty")
            } else {
                checkBody(x.request, reqCt, obj(rb["content"]), "request", ::add)
            }
        } else if (hasReqBody && method in listOf("get", "head", "delete")) {
            add(Severity.INFO, "openapi.unexpected-body", "Request body sent but the spec defines none for ${x.request.method} ${route.template}")
        }

        // Response.
        val res = x.response ?: return out
        val responses = obj(op["responses"])
        val code = res.status.toString()
        val key = listOf(code, code[0] + "XX", code[0] + "xx", "default").firstOrNull { responses.containsKey(it) }
        if (key == null) {
            add(Severity.WARNING, "openapi.undocumented-status", "Response status ${res.status} is not documented (documented: ${responses.keys.joinToString(", ")})")
            return out
        }
        val rd = resolve(responses[key])
        for ((hn, hv) in obj(rd["headers"])) {
            if (resolve(hv)["required"] == true && res.header(hn) == null)
                add(Severity.WARNING, "openapi.missing-response-header", "Documented required response header '$hn' is missing")
        }
        val content = obj(rd["content"])
        if (res.body.isNotEmpty()) {
            if (content.isEmpty() && rd.isNotEmpty() && res.status != 204)
                add(Severity.INFO, "openapi.unexpected-response-body", "Response has a body but status $key documents no content")
            else if (content.isNotEmpty()) checkBody(res, res.contentType, content, "response", ::add)
        }
        return out
    }

    private fun checkBody(m: HttpMsg, ct: String?, content: Map<String, Any?>, what: String, add: (Severity, String, String) -> Unit) {
        if (content.isEmpty()) return
        if (ct == null) { add(Severity.ERROR, "openapi.missing-content-type", "$what has a body but no Content-Type"); return }
        val mt = content.keys.firstOrNull { mediaMatches(it, ct) }
        if (mt == null) {
            add(Severity.ERROR, "openapi.content-type-mismatch", "$what Content-Type '$ct' is not allowed (spec: ${content.keys.joinToString(", ")})")
            return
        }
        val schema = resolve(obj(content[mt])["schema"])
        if (schema.isEmpty() || !(ct.contains("json"))) return
        val bytes = HttpExchanges.decodedBody(m) ?: return
        if (m.truncated || bytes.size >= HttpExchanges.MAX_DECODED) return
        val parsed = try { Json.parse(String(bytes, Charsets.UTF_8)) } catch (e: Exception) {
            add(Severity.ERROR, "openapi.invalid-json", "$what body is not valid JSON: ${e.message?.take(100)}"); return
        }
        val errs = ArrayList<String>()
        validateSchema(parsed, schema, "$", errs, 0)
        for (e in errs.take(MAX_ERRORS)) add(Severity.ERROR, "openapi.schema-violation", "$what body: $e")
        if (errs.size > MAX_ERRORS) add(Severity.ERROR, "openapi.schema-violation", "$what body: ${errs.size - MAX_ERRORS} more schema violations omitted")
    }

    private fun mediaMatches(spec: String, actual: String): Boolean {
        val s = spec.substringBefore(';').trim().lowercase()
        if (s == "*/*" || s == actual) return true
        if (s.endsWith("/*")) return actual.startsWith(s.dropLast(1))
        return false
    }

    // ── schema ────────────────────────────────────────────────────────────
    private fun typeOf(v: Any?): String = when (v) {
        null -> "null"; is Boolean -> "boolean"; is String -> "string"; is Map<*, *> -> "object"; is List<*> -> "array"
        is Number -> if (v.toDouble() == Math.floor(v.toDouble()) && !v.toDouble().isInfinite()) "integer" else "number"
        else -> "unknown"
    }

    private fun typeOk(v: Any?, t: String): Boolean = when (t) {
        "number" -> v is Number
        "integer" -> v is Number && typeOf(v) == "integer"
        else -> typeOf(v) == t
    }

    /** Collects violations of [schema] by [v] into [errs]; supports a practical JSON-Schema subset. */
    fun validateSchema(v: Any?, schema0: Map<String, Any?>, at: String, errs: MutableList<String>, depth: Int) {
        if (depth > 32 || errs.size > 200) return
        val schema = resolve(schema0)
        if (schema.isEmpty()) return
        if (v == null && (schema["nullable"] == true)) return
        val t = schema["type"]
        val types = when (t) { is String -> listOf(t); is List<*> -> t.map { it.toString() }; else -> emptyList() }
        if (types.isNotEmpty() && types.none { typeOk(v, it) } && !(v == null && "null" in types)) {
            errs.add("$at: expected ${types.joinToString("|")} but got ${typeOf(v)}"); return
        }
        schema["enum"]?.let { e -> if (e is List<*> && e.none { sameValue(it, v) }) errs.add("$at: value ${show(v)} is not one of ${e.joinToString(", ") { show(it) }}") }
        if (schema.containsKey("const") && !sameValue(schema["const"], v)) errs.add("$at: value must equal ${show(schema["const"])}")
        list(schema["allOf"]).forEach { validateSchema(v, obj(it), at, errs, depth + 1) }
        val any = list(schema["anyOf"])
        if (any.isNotEmpty() && any.none { sub -> ArrayList<String>().also { validateSchema(v, obj(sub), at, it, depth + 1) }.isEmpty() })
            errs.add("$at: does not match any of the anyOf schemas")
        val one = list(schema["oneOf"])
        if (one.isNotEmpty()) {
            val n = one.count { sub -> ArrayList<String>().also { validateSchema(v, obj(sub), at, it, depth + 1) }.isEmpty() }
            if (n != 1) errs.add("$at: matches $n of the oneOf schemas (exactly 1 required)")
        }
        when (v) {
            is Map<*, *> -> {
                val props = obj(schema["properties"])
                for (r in list(schema["required"])) if (!v.containsKey(r.toString())) errs.add("$at: missing required property '$r'")
                for ((k, value) in v) {
                    val sub = props[k.toString()]
                    if (sub != null) validateSchema(value, obj(sub), "$at.$k", errs, depth + 1)
                    else when (val ap = schema["additionalProperties"]) {
                        false -> errs.add("$at: additional property '$k' is not allowed")
                        is Map<*, *> -> validateSchema(value, obj(ap), "$at.$k", errs, depth + 1)
                    }
                }
            }
            is List<*> -> {
                val items = obj(schema["items"])
                if (items.isNotEmpty()) v.forEachIndexed { i, e -> validateSchema(e, items, "$at[$i]", errs, depth + 1) }
                (schema["minItems"] as? Number)?.let { if (v.size < it.toInt()) errs.add("$at: has ${v.size} items, minimum ${it.toInt()}") }
                (schema["maxItems"] as? Number)?.let { if (v.size > it.toInt()) errs.add("$at: has ${v.size} items, maximum ${it.toInt()}") }
            }
            is String -> {
                (schema["minLength"] as? Number)?.let { if (v.length < it.toInt()) errs.add("$at: shorter than minLength ${it.toInt()}") }
                (schema["maxLength"] as? Number)?.let { if (v.length > it.toInt()) errs.add("$at: longer than maxLength ${it.toInt()}") }
                (schema["pattern"] as? String)?.let { p ->
                    val ok = try { Regex(p).containsMatchIn(v) } catch (_: Exception) { true }
                    if (!ok) errs.add("$at: does not match pattern $p")
                }
            }
            is Number -> {
                (schema["minimum"] as? Number)?.let { if (v.toDouble() < it.toDouble()) errs.add("$at: ${show(v)} is below minimum ${show(it)}") }
                (schema["maximum"] as? Number)?.let { if (v.toDouble() > it.toDouble()) errs.add("$at: ${show(v)} is above maximum ${show(it)}") }
            }
        }
    }

    private fun checkScalar(raw: String, schema: Map<String, Any?>): String? {
        val t = schema["type"] as? String
        val v: Any? = when (t) {
            "integer" -> raw.toLongOrNull()?.toDouble() ?: return "expected integer"
            "number" -> raw.toDoubleOrNull() ?: return "expected number"
            "boolean" -> if (raw == "true" || raw == "false") raw.toBoolean() else return "expected boolean"
            else -> raw
        }
        val errs = ArrayList<String>()
        validateSchema(v, schema, "value", errs, 0)
        return errs.firstOrNull()?.substringAfter(": ")
    }

    private fun sameValue(a: Any?, b: Any?): Boolean =
        if (a is Number && b is Number) a.toDouble() == b.toDouble() else a == b

    private fun show(v: Any?): String = when (v) {
        is Double -> if (v == Math.floor(v) && !v.isInfinite()) v.toLong().toString() else v.toString()
        is String -> "\"$v\""
        else -> v.toString()
    }

    private fun decode(s: String) = try { URLDecoder.decode(s.replace("+", "%2B"), "UTF-8") } catch (_: Exception) { s }

    private fun parseQuery(q: String): Map<String, List<String>> {
        val m = LinkedHashMap<String, MutableList<String>>()
        for (kv in q.split('&')) {
            if (kv.isEmpty()) continue
            val k = decode(kv.substringBefore('=')); val v = try { URLDecoder.decode(kv.substringAfter('=', ""), "UTF-8") } catch (_: Exception) { kv.substringAfter('=', "") }
            m.getOrPut(k) { ArrayList() }.add(v)
        }
        return m
    }
}
