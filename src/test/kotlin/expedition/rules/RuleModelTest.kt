package expedition.rules

import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.server.Json
import expedition.session.ConfigCodec
import expedition.session.SavedConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class RuleMatcherTest {
    private fun req(s: String) = HttpHead.parse(s, true)!!
    private fun resp(s: String) = HttpHead.parse(s, false)!!

    private val post = req("POST /api/v1/login?next=/home HTTP/1.1\r\nHost: api.example.com:8443\r\nX-Debug: on\r\nContent-Type: application/json")
    private fun ctx(r: HttpHead = post, body: String? = """{"user":"admin"}""", listener: String = "web", port: Int = 8443,
                    response: HttpHead? = null, responseBody: String? = null) =
        MatchContext(listener, 7, "10.0.0.1", port, r, body?.toByteArray(), response, responseBody?.toByteArray())

    @Test
    fun `empty matcher matches every request`() = assertTrue(RuleMatcher().matches(ctx()))

    @Test
    fun `host glob, port, method list, path glob and path regex`() {
        assertTrue(RuleMatcher(host = "*.EXAMPLE.com").matches(ctx()))
        assertFalse(RuleMatcher(host = "example.com").matches(ctx()))
        assertTrue(RuleMatcher(port = 8443).matches(ctx()))
        assertFalse(RuleMatcher(port = 80).matches(ctx()))
        assertTrue(RuleMatcher(method = "get|post").matches(ctx()))
        assertFalse(RuleMatcher(method = "GET,PUT").matches(ctx()))
        assertTrue(RuleMatcher(path = "/api/*/login").matches(ctx()))
        assertFalse(RuleMatcher(path = "/api/v1/login?next=/home").matches(ctx()), "path glob ignores the query")
        assertTrue(RuleMatcher(pathRegex = "next=/h").matches(ctx()), "regex sees path+query")
        assertFalse(RuleMatcher(pathRegex = "^/other").matches(ctx()))
    }

    @Test
    fun `host falls back to the upstream host when the request has none`() {
        val noHost = req("GET / HTTP/1.0")
        assertTrue(RuleMatcher(host = "10.0.0.*").matches(ctx(noHost)))
    }

    @Test
    fun `headers, body regex, listener and connection id`() {
        assertTrue(RuleMatcher(headers = listOf(HeaderMatch("x-debug"))).matches(ctx()))
        assertTrue(RuleMatcher(headers = listOf(HeaderMatch("X-Debug", "^ON$"))).matches(ctx()))
        assertFalse(RuleMatcher(headers = listOf(HeaderMatch("X-Missing"))).matches(ctx()))
        assertTrue(RuleMatcher(bodyRegex = "\"user\":\"adm").matches(ctx()))
        assertFalse(RuleMatcher(bodyRegex = "root").matches(ctx()))
        assertFalse(RuleMatcher(bodyRegex = "x").matches(ctx(body = null)), "body matcher needs a body")
        assertTrue(RuleMatcher(bodyRegex = "x").matchesHead(ctx(body = null)), "head match ignores the body")
        assertTrue(RuleMatcher(listener = "WEB").matches(ctx()))
        assertFalse(RuleMatcher(listener = "other").matches(ctx()))
        assertTrue(RuleMatcher(connectionId = 7).matches(ctx()))
        assertFalse(RuleMatcher(connectionId = 8).matches(ctx()))
    }

    @Test
    fun `response direction matches status, response headers and body`() {
        val r = resp("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html")
        val m = RuleMatcher(direction = RuleDirection.RESPONSE, path = "/api/*", status = 500,
            headers = listOf(HeaderMatch("content-type", "html")), bodyRegex = "stack trace")
        assertTrue(m.matches(ctx(response = r, responseBody = "a stack trace here")))
        assertFalse(m.matches(ctx(response = r, responseBody = "fine")))
        assertFalse(m.matches(ctx()), "no response yet")
        assertFalse(RuleMatcher(status = 500).matches(ctx(response = r)), "status only applies to response rules")
    }

    @Test
    fun `catastrophic regex is cut off by the step budget`() {
        val m = RuleMatcher(bodyRegex = "(a+)+b")
        val start = System.nanoTime()
        assertFalse(m.matches(ctx(body = "a".repeat(5000))))
        assertTrue(System.nanoTime() - start < 5_000_000_000L)
    }

    @Test
    fun `validation rejects bad regex, port and status`() {
        assertThrows<Exception> { RuleMatcher(pathRegex = "(").validate() }
        assertThrows<IllegalArgumentException> { RuleMatcher(port = 70000).validate() }
        assertThrows<IllegalArgumentException> { HttpRule(times = 0).validate() }
        assertThrows<IllegalArgumentException> { RuleAction.Redirect("ftp://x") }
        assertThrows<IllegalArgumentException> { RuleAction.Delay(-1) }
    }

    @Test
    fun `mock response wire form`() {
        val m = RuleAction.MockResponse(201, null, listOf("X-A" to "1", "Transfer-Encoding" to "chunked"), BodySource.Hex("6869"))
        assertEquals("HTTP/1.1 201 Created\r\nX-A: 1\r\nContent-Length: 2\r\n\r\nhi", String(m.toBytes()))
        assertEquals("HTTP/1.1 201 Created\r\nX-A: 1\r\nContent-Length: 2\r\n\r\n", String(m.toBytes(forHead = true)))
    }

    @Test
    fun `transform rewrites headers, decoded body and status`() {
        val gz = java.io.ByteArrayOutputStream().also { o -> java.util.zip.GZIPOutputStream(o).use { it.write("secret=1".toByteArray()) } }.toByteArray()
        val head = resp("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nX-Old: 1\r\nContent-Length: ${gz.size}")
        val t = Transform(setHeaders = listOf("X-New" to "2"), removeHeaders = listOf("x-old"),
            bodyReplace = listOf("secret=(\\d)" to "secret=[$1]"), status = 418)
        val (h, b) = Transforms.apply(head, gz, t)
        assertEquals("secret=[1]", String(b))
        assertEquals(418, h.status)
        assertNull(h.header("content-encoding"))
        assertNull(h.header("x-old"))
        assertEquals("2", h.header("x-new"))
    }
}

class RulesEngineTest {
    private fun rule(name: String, times: Int? = null, listener: String? = null) =
        HttpRule(name = name, matcher = RuleMatcher(listener = listener), actions = listOf(RuleAction.Close), times = times)

    @Test
    fun `ids, update, enable, move, reorder, remove`() {
        val e = RulesEngine()
        var changes = 0
        e.onChange = { changes++ }
        val a = e.add(rule("a")); val b = e.add(rule("b")); val c = e.add(rule("c"), index = 0)
        assertEquals(listOf("c", "a", "b"), e.rules().map { it.name })
        assertEquals(3, setOf(a.id, b.id, c.id).size)
        assertTrue(e.moveTo(c.id, 99))
        assertEquals(listOf("a", "b", "c"), e.rules().map { it.name })
        e.reorder(listOf(b.id, c.id, a.id))
        assertEquals(listOf("b", "c", "a"), e.rules().map { it.name })
        assertThrows<IllegalArgumentException> { e.reorder(listOf(a.id)) }
        assertTrue(e.setEnabled(a.id, false))
        assertFalse(e.get(a.id)!!.enabled)
        assertEquals("a2", e.update(a.id, rule("a2"))!!.name)
        assertEquals(a.id, e.rules().last().id)
        assertTrue(e.remove(b.id))
        assertFalse(e.remove(b.id))
        assertTrue(changes >= 7)
    }

    @Test
    fun `times budget is consumed atomically and exhausts the rule`() {
        val e = RulesEngine()
        val r = e.add(rule("once", times = 2))
        assertTrue(e.hasActive())
        assertTrue(e.tryConsume(r)); assertTrue(e.tryConsume(r)); assertFalse(e.tryConsume(r))
        assertEquals(2, e.hitCount(r.id))
        assertFalse(e.hasActive())
        e.resetHits(r.id)
        assertTrue(e.hasActive())
    }

    @Test
    fun `hasActive honours direction, enabled and listener scoping`() {
        val e = RulesEngine()
        assertFalse(e.hasActive())
        val r = e.add(rule("x", listener = "web"))
        assertTrue(e.hasActive(RuleDirection.REQUEST, "WEB"))
        assertFalse(e.hasActive(RuleDirection.REQUEST, "redis"))
        assertFalse(e.hasActive(RuleDirection.RESPONSE))
        e.setEnabled(r.id, false)
        assertFalse(e.hasActive())
    }
}

class RuleCodecTest {
    init { RulesTestFiles.file("x.txt", "file body".toByteArray()) }
    private val json = """
        {"name":"all","times":3,"enabled":false,
         "match":{"direction":"request","method":"POST","host":"*.ex.com","port":443,"path":"/p/*","pathRegex":"q=\\d",
                  "headers":[{"name":"X-A","value":"^1$"},{"name":"X-B"}],"bodyRegex":"user","listener":"web","connectionId":4},
         "actions":[
           {"type":"delay","ms":10,"jitterMs":5},
           {"type":"transformRequest","setHeaders":{"X-S":"1"},"removeHeaders":["Cookie"],"replace":[{"regex":"a","with":"b"}],"urlReplace":{"regex":"^/p","with":"/q"}},
           {"type":"transformResponse","bodyHex":"00ff","status":202},
           {"type":"breakpoint","request":false,"response":true},
           {"type":"webhook","url":"http://127.0.0.1:1/h","respond":true},
           {"type":"redirect","url":"https://other:8443","keepHost":true},
           {"type":"mock","status":404,"reason":"Nope","headers":["Content-Type: text/plain"],"bodyFile":"x.txt"},
           {"type":"timeout"},{"type":"close"},{"type":"reset"},{"type":"passthrough"}]}
    """.trimIndent()

    @Test
    fun `json round-trips every matcher field and action type`() {
        val r = RuleCodec.fromJson(json)
        assertEquals(11, r.actions.size)
        assertEquals(RuleAction.Delay(10, 5), r.actions[0])
        assertEquals(RuleAction.MockResponse(404, "Nope", listOf("Content-Type" to "text/plain"), BodySource.FromFile.load("x.txt")), r.actions[6])
        assertEquals("file body", String((r.actions[6] as RuleAction.MockResponse).body.bytes()))
        val again = RuleCodec.fromJson(RuleCodec.toJson(r))
        assertEquals(r, again)
        assertEquals(r.matcher, again.matcher)
    }

    @Test
    fun `bad input is rejected with IllegalArgumentException`() {
        assertThrows<IllegalArgumentException> { RuleCodec.fromJson("""{"match":{},"actions":[{"type":"nope"}]}""") }
        assertThrows<IllegalArgumentException> { RuleCodec.fromJson("""{"match":{"direction":"sideways"},"actions":[]}""") }
        assertThrows<IllegalArgumentException> { RuleCodec.fromJson("""{"match":{},"actions":[{"type":"mock","bodyHex":"zz"}]}""") }
        assertThrows<IllegalArgumentException> { RuleCodec.fromJson("""{"match":{}}""") }
        // empty action list defaults to passthrough
        assertEquals(listOf(RuleAction.PassThrough), RuleCodec.fromJson("""{"match":{},"actions":[]}""").actions)
    }

    @Test
    fun `persistence round-trip through ConfigCodec keeps order and skips invalid rules with a warning`() {
        val r1 = RuleCodec.fromJson(json).copy(id = 5)
        val r2 = HttpRule(id = 9, name = "second", matcher = RuleMatcher(direction = RuleDirection.RESPONSE, status = 500),
            actions = listOf(RuleAction.TransformResponse(Transform(status = 200))))
        val text = ConfigCodec.encode(SavedConfig(httpRules = listOf(r1, r2)))
        val decoded = ConfigCodec.decode(text)
        assertEquals(listOf(r1, r2), decoded.config.httpRules)
        assertTrue(decoded.warnings.isEmpty())

        @Suppress("UNCHECKED_CAST")
        val root = Json.asObject(Json.parse(text)).toMutableMap()
        root["httpRules"] = (root["httpRules"] as List<Any?>) + mapOf("name" to "broken", "match" to mapOf<String, Any>(), "actions" to listOf(mapOf("type" to "bogus")))
        val withBad = ConfigCodec.decode(Json.obj(root))
        assertEquals(2, withBad.config.httpRules.size)
        assertTrue(withBad.warnings.single().contains("broken"))
    }
}

class RulesApiTest {
    private val registry = ConnectionRegistry()
    private val engine = RulesEngine()
    private val api = RulesApi(engine, registry)
    private fun call(method: String, path: String, body: String = ""): Pair<Int, Map<String, Any?>> =
        api.handle(method, path, body).let { (c, j) -> c to Json.asObject(Json.parse(j)) }

    private fun idOf(o: Map<String, Any?>) = (Json.asObject(o["rule"])["id"] as Number).toLong()

    @Test
    fun `crud, enable, move, reorder, webhooks toggle`() {
        val (c1, a) = call("POST", "/rules", """{"name":"a","match":{"path":"/a"},"actions":[{"type":"mock","status":204}]}""")
        assertEquals(200, c1)
        val b = call("POST", "/rules", """{"name":"b","match":{},"actions":[{"type":"close"}]}""").second
        val c = call("POST", "/rules", """{"name":"c","index":0,"match":{},"actions":[{"type":"reset"}]}""").second
        val (ia, ib, ic) = listOf(idOf(a), idOf(b), idOf(c))
        assertEquals(listOf("c", "a", "b"), engine.rules().map { it.name })

        val list = call("GET", "/rules").second
        assertEquals(3, (list["rules"] as List<*>).size)
        assertEquals(0, (Json.asObject((list["rules"] as List<*>)[0])["hits"] as Number).toInt())

        assertEquals("a", Json.asObject(call("GET", "/rules/$ia").second["rule"])["name"])
        assertEquals(404, call("GET", "/rules/999").first)

        call("PUT", "/rules/$ia", """{"name":"a2","match":{},"actions":[{"type":"timeout"}]}""")
        assertEquals("a2", engine.get(ia)!!.name)
        assertEquals(listOf(RuleAction.Timeout), engine.get(ia)!!.actions)

        call("POST", "/rules/$ib/enable", """{"enabled":false}""")
        assertFalse(engine.get(ib)!!.enabled)
        call("POST", "/rules/$ic/move", """{"to":2}""")
        assertEquals(listOf(ia, ib, ic), engine.rules().map { it.id })
        call("POST", "/rules/reorder", """{"ids":[$ic,$ib,$ia]}""")
        assertEquals(listOf(ic, ib, ia), engine.rules().map { it.id })
        assertThrows<IllegalArgumentException> { call("POST", "/rules/reorder", """{"ids":[$ic]}""") }

        assertEquals(true, call("POST", "/rules/webhooks", """{"enabled":true}""").second["webhooksEnabled"])
        assertTrue(engine.webhooksEnabled)

        assertEquals(200, call("DELETE", "/rules/$ib").first)
        assertEquals(404, call("DELETE", "/rules/$ib").first)
        call("DELETE", "/rules")
        assertTrue(engine.rules().isEmpty())
        assertThrows<IllegalArgumentException> { call("POST", "/rules", """{"match":{},"actions":[{"type":"zzz"}]}""") }
        assertEquals(404, call("PATCH", "/rules").first)
    }

    @Test
    fun `from-message builds a mock rule from a recorded keep-alive exchange`() {
        val conn = registry.openConnection("web", Protocol.TCP, "c", "u:80")
        registry.recordMessage(conn, Direction.CLIENT_TO_UPSTREAM, "GET /first HTTP/1.1\r\nHost: a.test\r\n\r\n".toByteArray())
        registry.recordMessage(conn, Direction.UPSTREAM_TO_CLIENT, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray())
        val second = registry.recordMessage(conn, Direction.CLIENT_TO_UPSTREAM, "POST /second HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\n\r\nx".toByteArray())
        registry.recordMessage(conn, Direction.UPSTREAM_TO_CLIENT, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".toByteArray())

        // preview only (add=false), by message id
        val (code, o) = call("POST", "/rules/from-message", """{"connection_id":$conn,"message_id":${second.id},"add":false}""")
        assertEquals(200, code)
        assertTrue(engine.rules().isEmpty())
        val preview = RuleCodec.fromMap(Json.asObject(o["rule"]))
        assertEquals(RuleMatcher(method = "POST", host = "a.test", path = "/second"), preview.matcher)
        assertEquals(RuleAction.MockResponse(201, "Created", listOf("Content-Type" to "application/json"), BodySource.Text("{}")), preview.actions.single())

        // by index, added to the engine
        call("POST", "/rules/from-message", """{"connection_id":$conn,"index":0}""")
        val added = engine.rules().single()
        assertEquals("/first", added.matcher.path)
        assertEquals("ok", String((added.actions.single() as RuleAction.MockResponse).body.bytes()))

        assertEquals(404, call("POST", "/rules/from-message", """{"connection_id":12345}""").first)
        assertThrows<IllegalArgumentException> { call("POST", "/rules/from-message", """{"connection_id":$conn,"index":7}""") }
    }
}
