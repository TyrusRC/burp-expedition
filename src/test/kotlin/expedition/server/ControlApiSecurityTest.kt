package expedition.server

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.script.ScriptHooks
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/** H1: mandatory token, path confinement, browser/injection guards on the control API. */
class ControlApiSecurityTest {

    private lateinit var server: ControlApiServer
    private lateinit var dataDir: File
    private lateinit var outside: File
    private val scripts = ScriptHooks()
    private var port = 0
    private val http = HttpClient.newHttpClient()

    @BeforeEach fun setUp() {
        val root = Files.createTempDirectory("api-sec").toFile()
        dataDir = File(root, "data").also { it.mkdirs() }
        outside = File(root, "outside").also { it.mkdirs() }
        port = ServerSocket(0).use { it.localPort }
        server = newServer(port, authToken = null) // auto-generated token
        server.start()
    }

    @AfterEach fun tearDown() { server.stop(); dataDir.parentFile.deleteRecursively() }

    private fun newServer(p: Int, authToken: String?, host: String = "127.0.0.1", explicit: Boolean = authToken != null) =
        ControlApiServer(
            host = host, port = p,
            registry = ConnectionRegistry(), matchReplace = MatchReplaceEngine(), intercept = InterceptController(),
            startListener = {}, stopListener = {}, runningListeners = { emptySet() },
            scriptHooks = scripts, authToken = authToken, tokenExplicit = explicit, dataDir = dataDir,
        )

    private fun post(path: String, body: String, token: String? = server.token): HttpResponse<String> {
        val b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path")).POST(HttpRequest.BodyPublishers.ofString(body))
        if (token != null) b.header("Authorization", "Bearer $token")
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString())
    }

    @Test fun `without a configured token a random one is generated and required on every route`() {
        assertTrue(server.token.length >= 32)
        for (path in listOf("/script", "/session/save", "/setup/jvm/apply", "/setup/browser/apply", "/listeners")) {
            assertEquals(401, post(path, "{}", token = null).statusCode(), path)
            assertEquals(401, post(path, "{}", token = "wrong").statusCode(), path)
        }
        assertEquals(null, scripts.source)
        val ok = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port/status"))
            .header("Authorization", "Bearer ${server.token}").build(), HttpResponse.BodyHandlers.ofString())
        assertEquals(200, ok.statusCode())
    }

    @Test fun `non-loopback bind is refused unless the token was set explicitly`() {
        val p = ServerSocket(0).use { it.localPort }
        assertThrows<IllegalArgumentException> { newServer(p, authToken = null, host = "0.0.0.0").start() }
        assertThrows<IllegalArgumentException> { newServer(p, authToken = "generated-elsewhere", host = "0.0.0.0", explicit = false).start() }
    }

    @Test fun `session save is confined to the data dir`() {
        assertEquals(200, post("/session/save", """{"path":"s1.json"}""").statusCode())
        assertTrue(File(dataDir, "s1.json").isFile)

        val escape = File(outside, "pwn.json")
        for (p in listOf("../outside/pwn.json", escape.path, "/etc/expedition-pwn.json")) {
            val r = post("/session/save", Json.obj("path" to p))
            assertEquals(400, r.statusCode(), "$p -> ${r.body()}")
        }
        assertFalse(escape.exists())

        // A symlink inside the data dir must not lead outside it.
        val link = File(dataDir, "link")
        runCatching { Files.createSymbolicLink(link.toPath(), outside.toPath()) }.onSuccess {
            assertEquals(400, post("/session/save", """{"path":"link/x.json"}""").statusCode())
            assertFalse(File(outside, "x.json").exists())
        }
    }

    @Test fun `session load outside the data dir is refused`() {
        val f = File(outside, "s.json").also { it.writeText("{}") }
        assertEquals(400, post("/session/load", Json.obj("path" to f.path)).statusCode())
        assertEquals(400, post("/session/load", """{"path":"../outside/s.json"}""").statusCode())
    }

    @Test fun `setup truststore, ca and browser binary are restricted`() {
        val victim = File(outside, "victim.p12").also { it.writeText("keep") }
        assertEquals(400, post("/setup/jvm/undo", Json.obj("params" to mapOf("truststore" to victim.path))).statusCode())
        assertTrue(victim.exists(), "undo must not delete a file outside the data dir")
        assertEquals(400, post("/setup/jvm/apply", Json.obj("params" to mapOf("truststore" to "../outside/t.p12"))).statusCode())
        assertEquals(400, post("/setup/adb/apply", Json.obj("ca" to "/etc/passwd")).statusCode())
        for (bin in listOf("/bin/sh", "sh", "--renderer-cmd-prefix=x", "../../bin/sh"))
            assertEquals(400, post("/setup/browser/apply", Json.obj("params" to mapOf("binary" to bin))).statusCode(), bin)
        assertEquals(400, post("/setup/browser/apply", Json.obj("params" to mapOf("url" to "--gpu-launcher=/bin/sh"))).statusCode())
    }

    @Test fun `shell metacharacters in adb and frida params are rejected`() {
        for (bad in listOf("10.0.2.2;reboot", "a b", "\$(id)", "x`id`", "h|sh", "-oProxy"))
            assertEquals(400, post("/setup/adb/apply", Json.obj("reverse" to "no", "device_host" to bad, "proxy_type" to "http")).statusCode(), bad)
        assertEquals(400, post("/setup/adb/apply", Json.obj("serial" to "-a;ls")).statusCode())
        assertEquals(400, post("/setup/frida/apply", Json.obj("package" to "com.x;id")).statusCode())
        val docker = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port/setup/docker?gateway=a%3Bid"))
            .header("Authorization", "Bearer ${server.token}").build(), HttpResponse.BodyHandlers.ofString())
        assertEquals(400, docker.statusCode(), docker.body())
    }

    @Test fun `client_cert outside the data dir is refused`() {
        val r = post("/listeners", """{"name":"c","protocol":"tcp","bind_port":1,"upstream_host":"127.0.0.1","upstream_port":9,"client_cert":"/etc/passwd"}""")
        assertNotEquals(200, r.statusCode())
    }

    @Test fun `api token file is generated owner-only and reused, env token wins`() {
        val dir = File(dataDir, "tok")
        val a = ApiToken.resolve(null, dir)
        assertFalse(a.explicit)
        assertTrue(a.token.length >= 32)
        val perms = runCatching { Files.getPosixFilePermissions(a.file!!.toPath()) }.getOrNull()
        if (perms != null) assertEquals(setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms)
        assertEquals(a.token, ApiToken.resolve("  ", dir).token)
        val e = ApiToken.resolve("from-env", dir)
        assertTrue(e.explicit); assertEquals("from-env", e.token)
    }

    @Test fun `path sandbox resolves relative paths inside and rejects escapes`() {
        val sb = PathSandbox(dataDir)
        assertEquals(File(dataDir, "a/b.json").canonicalPath, sb.resolve("a/b.json").path)
        assertThrows<IllegalArgumentException> { sb.resolve("a/../../x") }
        assertThrows<IllegalArgumentException> { sb.resolve("/tmp/x") }
        assertThrows<IllegalArgumentException> { sb.resolve("") }
    }
}
