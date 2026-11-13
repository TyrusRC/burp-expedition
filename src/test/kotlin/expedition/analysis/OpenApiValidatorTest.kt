package expedition.analysis

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class OpenApiValidatorTest {
    private val yaml = """
openapi: 3.0.3
info:
  title: Pets
  version: "1"
servers:
  - url: https://api.example.com/v1
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
          required: true
          schema:
            type: integer
            minimum: 1
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: array
                items:
                  ${'$'}ref: "#/components/schemas/Pet"
        default:
          description: err
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              ${'$'}ref: "#/components/schemas/Pet"
      responses:
        "201":
          description: created
  /pets/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: integer
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                ${'$'}ref: "#/components/schemas/Pet"
        "4XX":
          description: client error
  /pets/mine:
    get:
      responses:
        "200":
          description: ok
components:
  schemas:
    Pet:
      type: object
      required: [id, name]
      properties:
        id:
          type: integer
        name:
          type: string
        kind:
          type: string
          enum: [cat, dog]
        tags:
          type: array
          items:
            type: string
"""
    private val spec = OpenApiSpec.parse(yaml)

    private fun v(req: String, res: String?) = spec.validate(exch(req, res))
    private fun codes(f: List<Finding>) = f.map { it.code }

    private fun getReq(path: String) = "GET $path HTTP/1.1\nHost: a\n\n"
    private fun json(status: Int, body: String) = resp(status, "Content-Type: application/json", body)

    @Test fun `parses yaml and json`() {
        assertEquals("Pets", spec.title)
        assertEquals(4, spec.operationCount)
        val j = OpenApiSpec.parse("""{"openapi":"3.1.0","info":{"title":"J"},"paths":{"/a":{"get":{"responses":{"200":{"description":"x"}}}}}}""")
        assertEquals("J", j.title); assertEquals(1, j.operationCount)
    }

    @Test fun `rejects non openapi 3`() {
        assertThrows(IllegalArgumentException::class.java) { OpenApiSpec.parse("swagger: '2.0'\npaths: {}") }
        assertThrows(IllegalArgumentException::class.java) { OpenApiSpec.parse("") }
        assertThrows(IllegalArgumentException::class.java) { OpenApiSpec.parse("openapi: 3.0.0") }
        assertThrows(IllegalArgumentException::class.java) { OpenApiSpec.parse("{bad") }
    }

    @Test fun `valid exchange has no findings`() {
        val f = v(getReq("/v1/pets?limit=5"), json(200, """[{"id":1,"name":"Rex","kind":"dog","tags":["a"]}]"""))
        assertEquals(emptyList<String>(), codes(f))
    }

    @Test fun `unknown path warns`() {
        assertEquals(listOf("openapi.path-not-found"), codes(v(getReq("/v1/nope"), null)))
    }

    @Test fun `method not allowed`() {
        val f = v("DELETE /v1/pets HTTP/1.1\nHost: a\n\n", null)
        assertEquals(listOf("openapi.method-not-allowed"), codes(f))
        assertEquals(Severity.ERROR, f[0].severity)
        assertTrue(f[0].message.contains("GET, POST"))
    }

    @Test fun `missing required query param`() {
        assertTrue("openapi.missing-parameter" in codes(v(getReq("/v1/pets"), null)))
    }

    @Test fun `invalid query param type and range`() {
        assertTrue("openapi.invalid-parameter" in codes(v(getReq("/v1/pets?limit=abc"), null)))
        assertTrue("openapi.invalid-parameter" in codes(v(getReq("/v1/pets?limit=0"), null)))
    }

    @Test fun `path param matched and typed, literal route wins over template`() {
        assertEquals(emptyList<String>(), codes(v(getReq("/v1/pets/7"), json(200, """{"id":7,"name":"a"}"""))))
        assertEquals(listOf("openapi.invalid-parameter"), codes(v(getReq("/v1/pets/xyz"), null)))
        assertEquals(emptyList<String>(), codes(v(getReq("/v1/pets/mine"), resp(200, "", ""))))
    }

    @Test fun `response status ranges and default`() {
        assertEquals(emptyList<String>(), codes(v(getReq("/v1/pets/7"), resp(404, "", ""))))
        assertEquals(listOf("openapi.undocumented-status"), codes(v(getReq("/v1/pets/7"), resp(500, "", ""))))
        assertEquals(emptyList<String>(), codes(v(getReq("/v1/pets?limit=1"), resp(503, "", ""))))
    }

    @Test fun `response schema violations`() {
        val f = v(getReq("/v1/pets/7"), json(200, """{"id":"x","kind":"fish"}"""))
        val msgs = f.filter { it.code == "openapi.schema-violation" }.map { it.message }
        assertTrue(msgs.any { it.contains("missing required property 'name'") }, msgs.toString())
        assertTrue(msgs.any { it.contains("\$.id") && it.contains("expected integer") }, msgs.toString())
        assertTrue(msgs.any { it.contains("\$.kind") && it.contains("not one of") }, msgs.toString())
    }

    @Test fun `response array items checked and content type mismatch`() {
        val bad = v(getReq("/v1/pets?limit=1"), json(200, """[{"id":1,"name":"a"},{"id":2}]"""))
        assertTrue(bad.any { it.message.contains("[1]") && it.message.contains("name") })
        val ct = v(getReq("/v1/pets/7"), resp(200, "Content-Type: text/plain", "hi"))
        assertTrue("openapi.content-type-mismatch" in codes(ct))
    }

    @Test fun `request body required, content type and schema`() {
        val body = """{"id":1}"""
        val post = "POST /v1/pets HTTP/1.1\nHost: a\nContent-Type: application/json\nContent-Length: ${body.length}\n\n$body"
        val f = v(post, resp(201, "", ""))
        assertEquals(listOf("openapi.schema-violation"), codes(f))
        assertTrue(f[0].message.startsWith("request body"))

        val none = v("POST /v1/pets HTTP/1.1\nHost: a\nContent-Length: 0\n\n", null)
        assertEquals(listOf("openapi.missing-body"), codes(none))

        val xml = "POST /v1/pets HTTP/1.1\nHost: a\nContent-Type: application/xml\nContent-Length: 3\n\n<a>"
        assertTrue("openapi.content-type-mismatch" in codes(v(xml, null)))

        val ok = """{"id":1,"name":"n"}"""
        val good = "POST /v1/pets HTTP/1.1\nHost: a\nContent-Type: application/json; charset=utf-8\nContent-Length: ${ok.length}\n\n$ok"
        assertEquals(emptyList<String>(), codes(v(good, resp(201, "", ""))))
    }

    @Test fun `invalid json body is an error`() {
        val f = v(getReq("/v1/pets/1"), json(200, "{nope"))
        assertTrue("openapi.invalid-json" in codes(f))
    }

    @Test fun `oneOf additionalProperties nullable and numeric bounds`() {
        val s = OpenApiSpec.parse("""
openapi: 3.0.0
info: {title: t, version: "1"}
paths: {}
""")
        fun errs(v: Any?, schema: String): List<String> {
            val e = ArrayList<String>()
            s.validateSchema(v, expedition.server.Json.asObject(expedition.server.Json.parse(schema)), "$", e, 0)
            return e
        }
        assertTrue(errs(1.0, """{"oneOf":[{"type":"integer"},{"type":"number"}]}""").isNotEmpty())
        assertTrue(errs(1.5, """{"oneOf":[{"type":"integer"},{"type":"number"}]}""").isEmpty())
        assertTrue(errs(null, """{"type":"string","nullable":true}""").isEmpty())
        assertTrue(errs(null, """{"type":"string"}""").isNotEmpty())
        assertTrue(errs(mapOf("a" to 1.0), """{"type":"object","additionalProperties":false}""").isNotEmpty())
        assertTrue(errs(5.0, """{"type":"number","maximum":3}""").isNotEmpty())
        assertTrue(errs("ab", """{"type":"string","minLength":3}""").isNotEmpty())
        assertTrue(errs("ab", """{"type":"string","pattern":"^a"}""").isEmpty())
        assertTrue(errs("x", """{"type":["string","null"]}""").isEmpty())
    }
}
