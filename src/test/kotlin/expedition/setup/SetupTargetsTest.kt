package expedition.setup

import expedition.tls.DefaultCa
import java.io.File
import java.nio.file.Files
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class FakeRunner(val responses: Map<String, CmdResult> = emptyMap()) : CommandRunner {
    val calls = mutableListOf<List<String>>()
    override fun run(args: List<String>, timeoutMs: Long): CmdResult {
        calls += args
        return responses[args.firstOrNull()] ?: CmdResult(0, "")
    }
    override fun spawn(args: List<String>): Process { calls += args; throw java.io.IOException("fake: no spawn") }
}

class SetupTargetsTest {
    private val dir = Files.createTempDirectory("setup-test").toFile()
    private val ca: File = run {
        val p = DefaultCa.ensureDefaultCa(dir, "pw".toCharArray()); File(dir, "expedition-ca.crt")
    }
    private fun ctx(params: Map<String, String> = emptyMap(), type: String = "socks5", runner: CommandRunner = FakeRunner()) =
        SetupContext(port = 9050, caCert = ca, proxyType = type, params = params, runner = runner)

    @Test fun terminalAllShells() {
        for (sh in listOf("bash", "zsh", "fish", "powershell", "cmd")) {
            val g = TerminalTarget.guide(ctx(mapOf("shell" to sh)))
            assertTrue("HTTPS_PROXY" in g && "NODE_EXTRA_CA_CERTS" in g && "GIT_SSL_CAINFO" in g, sh)
            assertTrue("socks5h://127.0.0.1:9050" in g)
        }
        assertTrue("set -gx HTTP_PROXY" in TerminalTarget.guide(ctx(mapOf("shell" to "fish"))))
        assertTrue("\$env:HTTP_PROXY = " in TerminalTarget.guide(ctx(mapOf("shell" to "powershell"))))
        assertTrue("http://127.0.0.1:9050" in TerminalTarget.guide(ctx(type = "http")))
    }

    @Test fun shQuoting() {
        assertEquals("'a b'", Sh.q("a b"))
        assertEquals("'it'\\''s'", Sh.q("it's"))
        assertEquals("'it''s'", Sh.ps("it's"))
    }

    @Test fun dockerFlagsComposeAndDistros() {
        val g = DockerTarget.guide(ctx())
        assertTrue("--add-host=host.docker.internal:host-gateway" in g)
        assertTrue("extra_hosts" in g && "HTTPS_PROXY" in g && ":ro" in g)
        assertTrue("apk add" in DockerTarget.guide(ctx(mapOf("distro" to "alpine"))))
        assertTrue("update-ca-trust" in DockerTarget.guide(ctx(mapOf("distro" to "rhel"))))
        assertTrue("update-ca-certificates" in DockerTarget.caUpdate("debian").last())
    }

    @Test fun osTarget() {
        assertTrue("update-ca-certificates" in OsTarget.guide(ctx()))
        assertTrue("update-ca-trust" in OsTarget.guide(ctx(mapOf("os" to "linux-rhel"))))
        assertTrue("security add-trusted-cert" in OsTarget.guide(ctx(mapOf("os" to "macos"))))
        assertTrue("certutil -addstore" in OsTarget.guide(ctx(mapOf("os" to "windows"))))
    }

    @Test fun jvmArgsAndTruststore() {
        val c = ctx(mapOf("truststore" to File(dir, "t.p12").path))
        val a = JvmTarget.jvmArgs(c)
        assertTrue("-DsocksProxyPort=9050" in a)
        assertTrue(a.any { it.startsWith("-Djavax.net.ssl.trustStore=") })
        assertTrue("-Dhttps.proxyHost=127.0.0.1" in JvmTarget.jvmArgs(ctx(type = "http")))
        val r = FakeRunner(mapOf("jcmd" to CmdResult(0, "123 com.foo.Main arg\n456 jdk.jcmd/sun.tools.jcmd.JCmd -l\n")))
        val res = JvmTarget.apply(ctx(mapOf("truststore" to File(dir, "t.p12").path), runner = r))
        assertTrue(res.ok, res.log)
        assertTrue("123 com.foo.Main" in res.log && "456" !in res.log)
        val ks = java.security.KeyStore.getInstance("PKCS12").apply { File(dir, "t.p12").inputStream().use { load(it, "changeit".toCharArray()) } }
        assertTrue(ks.containsAlias("expedition-ca"))
        assertTrue(JvmTarget.undo(c).ok)
    }

    @Test fun browserFlags() {
        val g = BrowserTarget.guide(ctx())
        assertTrue("--proxy-server=socks5://127.0.0.1:9050" in g)
        val spki = CaInfo.spkiHash(ca)!!
        assertTrue("--ignore-certificate-errors-spki-list=$spki" in g || "spki-list=${Sh.q(spki)}" in g || spki.take(10) in g)
        assertTrue("--proxy-server=http://" in BrowserTarget.proxyFlag(ctx(type = "http")))
        assertTrue("network.proxy.socks_version" in BrowserTarget.firefoxPrefs(ctx()))
    }

    @Test fun browserApplyMissingBinary() {
        val r = BrowserTarget.apply(ctx(mapOf("binary" to "no-such-browser-xyz")))
        assertFalse(r.ok)
    }

    @Test fun adbGuideAndCommands() {
        val g = AdbTarget.guide(ctx(mapOf("serial" to "emulator-5554")))
        assertTrue("adb -s emulator-5554 reverse tcp:9050 tcp:9050" in g)
        assertTrue("subject_hash_old" in g && "/system/etc/security/cacerts" in g)
        assertTrue("settings put global http_proxy 127.0.0.1:9050" in AdbTarget.guide(ctx(type = "http")))
        assertTrue("HTTP-only" in g)
        val cmds = AdbTarget.applyCommands(ctx(type = "http"))
        assertEquals(listOf("adb", "push"), cmds[0].take(2))
        assertTrue(cmds.any { it.contains("reverse") })
        assertTrue(AdbTarget.undoCommands(ctx()).any { it.contains(":0") })
        assertEquals("10.0.2.2:9050", AdbTarget.deviceProxy(ctx(mapOf("reverse" to "no"))))
    }

    @Test fun adbApplyBehaviour() {
        val missing = AdbTarget.apply(ctx(runner = FakeRunner(mapOf("adb" to CmdResult(-1, "nf", missing = true)))))
        assertFalse(missing.ok); assertTrue("adb not found" in missing.log)
        val none = AdbTarget.apply(ctx(runner = FakeRunner(mapOf("adb" to CmdResult(0, "List of devices attached\n\n")))))
        assertFalse(none.ok)
        val good = FakeRunner(mapOf("adb" to CmdResult(0, "List of devices attached\nemu\tdevice\n")))
        val ok = AdbTarget.apply(ctx(runner = good))
        assertTrue(ok.ok, ok.log)
        assertTrue(good.calls.any { it.contains("push") } && good.calls.any { it.contains("reverse") })
    }

    @Test fun fridaScriptAndArgs() {
        val js = FridaTarget.UNPIN_JS
        for (k in listOf("TrustManagerImpl", "CertificatePinner", "SSLContext", "SecTrustEvaluate", "NSURLSession")) assertTrue(k in js, k)
        val g = FridaTarget.guide(ctx(mapOf("package" to "com.acme.app")))
        assertTrue("frida -U -f com.acme.app -l" in g)
        assertTrue("EXPERIMENTAL" in g)
        assertTrue("-H" in FridaTarget.fridaArgs(ctx(mapOf("device" to "remote")), File("x.js")))
        val miss = FridaTarget.apply(ctx(runner = FakeRunner(mapOf("frida" to CmdResult(-1, "", missing = true)))))
        assertFalse(miss.ok); assertTrue("pip install frida-tools" in miss.log)
    }

    @Test fun burpChain() {
        val g = BurpChainTarget.guide(ctx())
        assertTrue("\"protocol\":\"socks5\"" in g && "\"tls\":\"mitm\"" in g && "\"bind_port\":9050" in g)
        assertTrue("SOCKS proxy port: 9050" in g && "Do DNS lookups over SOCKS proxy" in g)
        assertTrue("api-token" in g && "HTTP/2" in g && "502" in g)
        assertFalse("\"username\"" in g)
        val a = BurpChainTarget.guide(ctx(mapOf("username" to "bob", "password" to "s3cret")))
        assertTrue("\"username\":\"bob\",\"password\":\"s3cret\"" in a)
        val svc = SetupService(caDir = dir, runner = FakeRunner())
        assertEquals(400, svc.handle("GET", "/setup/burp-chain", "username=a'b", "").first)
        assertEquals(400, svc.handle("GET", "/setup/burp-chain", "username=bob&password=x'y", "").first)
        assertEquals(200, svc.handle("GET", "/setup/burp-chain", "username=bob&password=pw1", "").first)
    }

    @Test fun serviceRoutes() {
        val svc = SetupService(caDir = dir, runner = FakeRunner())
        val (c1, j1) = svc.handle("GET", "/setup/targets", null, "")
        assertEquals(200, c1)
        for (id in listOf("adb", "frida", "terminal", "docker", "jvm", "browser", "os", "burp-chain")) assertTrue("\"$id\"" in j1, id)
        val (c2, j2) = svc.handle("GET", "/setup/terminal", "port=7777&shell=fish", "")
        assertEquals(200, c2); assertTrue("7777" in j2 && "set -gx" in j2)
        assertEquals(404, svc.handle("GET", "/setup/nope", null, "").first)
        val (c3, j3) = svc.handle("POST", "/setup/jvm/apply", null, """{"port":1234,"params":{"truststore":"${File(dir, "z.p12").path}"}}""")
        assertEquals(200, c3, j3)
        assertEquals(404, svc.handle("GET", "/setup/terminal/apply", null, "").first)
    }

    @Test fun processRunnerMissingTool() {
        val r = ProcessRunner().run(listOf("definitely-not-a-tool-xyz"), 1000)
        assertTrue(r.missing && !r.ok)
    }

    // M8: values reaching `adb shell` (and other argv / generated files) are allow-listed.
    @Test fun injectionInSetupParamsIsRejected() {
        val bad = listOf("10.0.2.2;reboot", "a b", "\$(id)", "x`id`", "h|sh", "h&&id", "-x", "h'q", "h\"q", "h\nid")
        for (v in bad) {
            assertThrows(IllegalArgumentException::class.java, { AdbTarget.applyCommands(ctx(mapOf("reverse" to "no", "device_host" to v), type = "http")) }, v)
        }
        assertThrows(IllegalArgumentException::class.java) { AdbTarget.undoCommands(ctx(mapOf("serial" to "-s;ls"))) }
        assertThrows(IllegalArgumentException::class.java) { FridaTarget.fridaArgs(ctx(mapOf("package" to "com.a;id")), File("x.js")) }
        assertThrows(IllegalArgumentException::class.java) { FridaTarget.fridaArgs(ctx(mapOf("device" to "remote", "remote_host" to "h;id:1")), File("x.js")) }
        val svc = SetupService(caDir = dir, runner = FakeRunner())
        assertEquals(400, svc.handle("GET", "/setup/docker", "gateway=a%3Bid", "").first)
        assertEquals(400, svc.handle("GET", "/setup/jvm", "storepass=a%20b", "").first)
        assertEquals(400, svc.handle("GET", "/setup/terminal", "shell=sh%3Bid", "").first)
        assertEquals(400, svc.handle("GET", "/setup/terminal", "host=a%22b", "").first)
        // well-formed values still work
        val ok = AdbTarget.applyCommands(ctx(mapOf("reverse" to "no", "device_host" to "192.168.1.10", "serial" to "emulator-5554"), type = "http"))
        assertTrue(ok.any { "192.168.1.10:9050" in it })
        assertEquals("10.0.2.2:9050", AdbTarget.deviceProxy(ctx(mapOf("reverse" to "no"))))
    }

    @Test fun untrustedServiceConfinesPathsAndBinaries() {
        val svc = SetupService(caDir = dir, runner = FakeRunner(), untrusted = true)
        assertEquals(400, svc.handle("POST", "/setup/jvm/apply", null, """{"params":{"truststore":"/tmp/elsewhere.p12"}}""").first)
        assertEquals(200, svc.handle("POST", "/setup/jvm/apply", null, """{"params":{"truststore":"t.p12"}}""").first)
        assertTrue(File(dir, "t.p12").isFile)
        assertEquals(400, svc.handle("POST", "/setup/browser/apply", null, """{"params":{"binary":"/bin/sh"}}""").first)
        // a known browser name passes validation (FakeRunner then fails to spawn it -> 422, not 400)
        assertEquals(422, svc.handle("POST", "/setup/browser/apply", null, """{"params":{"binary":"chromium"}}""").first)
    }
}
