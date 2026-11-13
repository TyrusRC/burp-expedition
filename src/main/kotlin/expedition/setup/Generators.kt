package expedition.setup

import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate

/** Terminal env snippet for bash/zsh/fish/PowerShell/cmd. Pure. */
object TerminalTarget : SetupTarget {
    override val id = "terminal"
    override val title = "Terminal (env vars)"
    override val params = listOf(ParamSpec("shell", "Shell", "bash", listOf("bash", "zsh", "fish", "powershell", "cmd")))

    fun envVars(ctx: SetupContext): List<Pair<String, String>> {
        val u = ctx.proxyUrl
        return listOf(
            "HTTP_PROXY" to u, "HTTPS_PROXY" to u, "ALL_PROXY" to u,
            "http_proxy" to u, "https_proxy" to u, "all_proxy" to u,
            "SSL_CERT_FILE" to ctx.caPath, "NODE_EXTRA_CA_CERTS" to ctx.caPath,
            "REQUESTS_CA_BUNDLE" to ctx.caPath, "CURL_CA_BUNDLE" to ctx.caPath, "GIT_SSL_CAINFO" to ctx.caPath,
        )
    }

    fun render(shell: String, vars: List<Pair<String, String>>, unset: Boolean = false): String = vars.joinToString("\n") { (k, v) ->
        when (shell) {
            "fish" -> if (unset) "set -e $k" else "set -gx $k ${Sh.q(v)}"
            "powershell" -> if (unset) "Remove-Item Env:$k -ErrorAction SilentlyContinue" else "\$env:$k = ${Sh.ps(v)}"
            "cmd" -> if (unset) "set $k=" else "set ${Sh.cmd("$k=$v")}"
            else -> if (unset) "unset $k" else "export $k=${Sh.q(v)}"
        }
    }

    override fun guide(ctx: SetupContext): String {
        val shell = ctx.param("shell", "bash")
        val vars = envVars(ctx)
        return buildString {
            appendLine("# Paste into the terminal whose child processes should go through Expedition ($shell)")
            appendLine(render(shell, vars))
            appendLine()
            appendLine("# Undo")
            appendLine(render(shell, vars, unset = true))
            appendLine()
            appendLine("# Note: SSL_CERT_FILE & co. REPLACE the trust bundle with the Expedition CA only; tools reaching hosts outside the proxy may then fail verification.")
            if (ctx.proxyType != "http") appendLine("# Proxy URL is SOCKS5 (socks5h = DNS via proxy). Tools without SOCKS support need an HTTP-proxy front-end or proxychains.")
        }
    }
}

/** Docker flags / compose / in-container CA update. Pure. */
object DockerTarget : SetupTarget {
    override val id = "docker"
    override val title = "Docker container"
    override val params = listOf(
        ParamSpec("gateway", "Host name seen from container", "host.docker.internal"),
        ParamSpec("distro", "Container distro", "debian", listOf("debian", "alpine", "rhel")),
    )
    private const val CA_IN = "/usr/local/share/ca-certificates/expedition-ca.crt"

    fun caUpdate(distro: String): List<String> = when (distro) {
        "alpine" -> listOf("apk add --no-cache ca-certificates", "update-ca-certificates")
        "rhel" -> listOf("cp $CA_IN /etc/pki/ca-trust/source/anchors/expedition-ca.crt", "update-ca-trust extract")
        else -> listOf("apt-get update && apt-get install -y ca-certificates", "update-ca-certificates")
    }

    override fun guide(ctx: SetupContext): String {
        val gw = ctx.param("gateway", "host.docker.internal")
        val distro = ctx.param("distro", "debian")
        val url = (if (ctx.proxyType == "http") "http://" else "socks5h://") + "$gw:${ctx.port}"
        val envs = listOf("HTTP_PROXY" to url, "HTTPS_PROXY" to url, "ALL_PROXY" to url,
            "SSL_CERT_FILE" to CA_IN, "NODE_EXTRA_CA_CERTS" to CA_IN, "REQUESTS_CA_BUNDLE" to CA_IN, "CURL_CA_BUNDLE" to CA_IN)
        return buildString {
            appendLine("# docker run flags")
            appendLine("docker run --add-host=$gw:host-gateway \\")
            envs.forEach { (k, v) -> appendLine("  -e ${Sh.q("$k=$v")} \\") }
            appendLine("  -v ${Sh.q("${ctx.caPath}:$CA_IN:ro")} \\")
            appendLine("  <image>")
            appendLine()
            appendLine("# docker-compose service")
            appendLine("services:\n  app:\n    extra_hosts:\n      - \"$gw:host-gateway\"\n    environment:")
            envs.forEach { (k, v) -> appendLine("      $k: \"$v\"") }
            appendLine("    volumes:\n      - \"${ctx.caPath}:$CA_IN:ro\"")
            appendLine()
            appendLine("# Install the CA into the container's system store ($distro), run inside the container as root")
            caUpdate(distro).forEach { appendLine(it) }
            appendLine()
            appendLine("# The Expedition listener must be reachable from the container: bind 0.0.0.0 (or the docker0 gateway), not 127.0.0.1.")
        }
    }
}

/** Host OS trust-store commands. Pure. */
object OsTarget : SetupTarget {
    override val id = "os"
    override val title = "Operating system trust store"
    override val params = listOf(ParamSpec("os", "OS", "linux-debian", listOf("linux-debian", "linux-rhel", "linux-arch", "macos", "windows")))

    override fun guide(ctx: SetupContext): String {
        val ca = ctx.caPath
        val (install, remove) = when (ctx.param("os", "linux-debian")) {
            "linux-rhel" -> listOf("sudo cp ${Sh.q(ca)} /etc/pki/ca-trust/source/anchors/expedition-ca.crt", "sudo update-ca-trust extract") to
                listOf("sudo rm /etc/pki/ca-trust/source/anchors/expedition-ca.crt", "sudo update-ca-trust extract")
            "linux-arch" -> listOf("sudo trust anchor --store ${Sh.q(ca)}") to listOf("sudo trust anchor --remove ${Sh.q(ca)}")
            "macos" -> listOf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${Sh.q(ca)}") to
                listOf("sudo security remove-trusted-cert -d ${Sh.q(ca)}")
            "windows" -> listOf("certutil -addstore -f Root ${Sh.cmd(ca)}   (elevated prompt)") to
                listOf("certutil -delstore Root \"Expedition Auto CA\"")
            else -> listOf("sudo cp ${Sh.q(ca)} /usr/local/share/ca-certificates/expedition-ca.crt", "sudo update-ca-certificates") to
                listOf("sudo rm /usr/local/share/ca-certificates/expedition-ca.crt", "sudo update-ca-certificates --fresh")
        }
        return "# Install\n${install.joinToString("\n")}\n\n# Remove\n${remove.joinToString("\n")}\n\n" +
            "# Firefox and JVM keep their own stores; use the Chromium/Firefox and JVM targets for those.\n"
    }
}

/** JVM flags + truststore generation (default cacerts + Expedition CA). */
object JvmTarget : SetupTarget {
    override val id = "jvm"
    override val title = "JVM (flags + truststore)"
    override val executable = true
    override val params = listOf(
        ParamSpec("truststore", "Truststore path (blank = auto)"),
        ParamSpec("storepass", "Truststore password", "changeit"),
    )

    fun trustPath(ctx: SetupContext) = ctx.param("truststore", File(ctx.workDir, "expedition-truststore.p12").absolutePath)

    fun jvmArgs(ctx: SetupContext): List<String> {
        val pw = ctx.param("storepass", "changeit")
        val proxy = if (ctx.proxyType == "http") listOf(
            "-Dhttp.proxyHost=${ctx.host}", "-Dhttp.proxyPort=${ctx.port}",
            "-Dhttps.proxyHost=${ctx.host}", "-Dhttps.proxyPort=${ctx.port}", "-Dhttp.nonProxyHosts=",
        ) else listOf("-DsocksProxyHost=${ctx.host}", "-DsocksProxyPort=${ctx.port}")
        return proxy + listOf(
            "-Djavax.net.ssl.trustStore=${trustPath(ctx)}", "-Djavax.net.ssl.trustStorePassword=$pw",
            "-Djavax.net.ssl.trustStoreType=PKCS12",
        )
    }

    /** Parses `jcmd -l` into (pid, description). */
    fun parseJcmd(out: String): List<Pair<Int, String>> = out.lines().mapNotNull { l ->
        val m = Regex("^(\\d+)\\s+(.*)$").find(l.trim()) ?: return@mapNotNull null
        if (m.groupValues[2].contains("JCmd") || m.groupValues[2].contains("jdk.jcmd")) null
        else m.groupValues[1].toInt() to m.groupValues[2]
    }

    /** Builds a PKCS12 truststore = [base] entries (if any) + [ca]. Pure aside from the stream. */
    fun buildTruststore(ca: X509Certificate, base: KeyStore?, password: CharArray, out: java.io.OutputStream) {
        val ks = KeyStore.getInstance("PKCS12").apply { load(null, password) }
        base?.aliases()?.toList()?.forEach { a -> base.getCertificate(a)?.let { ks.setCertificateEntry("base-$a", it) } }
        ks.setCertificateEntry("expedition-ca", ca)
        ks.store(out, password)
    }

    private fun defaultCacerts(): KeyStore? = runCatching {
        val f = File(System.getProperty("java.home"), "lib/security/cacerts")
        KeyStore.getInstance(KeyStore.getDefaultType()).also { ks -> f.inputStream().use { ks.load(it, "changeit".toCharArray()) } }
    }.getOrNull()

    override fun guide(ctx: SetupContext): String {
        val args = jvmArgs(ctx)
        val pw = ctx.param("storepass", "changeit")
        return buildString {
            appendLine("# JVM arguments")
            appendLine(args.joinToString(" ") { Sh.q(it) })
            appendLine()
            appendLine("# or via environment")
            appendLine("export JAVA_TOOL_OPTIONS=${Sh.q(args.joinToString(" "))}")
            appendLine()
            appendLine("# Build the truststore yourself (Apply does this for you and also copies the JDK's default cacerts into it)")
            appendLine(Sh.join(listOf("keytool", "-importcert", "-noprompt", "-alias", "expedition-ca", "-file", ctx.caPath,
                "-keystore", trustPath(ctx), "-storetype", "PKCS12", "-storepass", pw)))
            appendLine()
            appendLine("# Running JVMs: list with `jcmd -l`. System properties cannot be changed in a live JVM by jcmd/jattach alone;")
            appendLine("# restart the process with the arguments above (or use an agent that calls System.setProperty).")
        }
    }

    override fun apply(ctx: SetupContext): ActionResult {
        val ca = CaInfo.load(ctx.caCert) ?: return ActionResult(false, "cannot read CA certificate at ${ctx.caPath}")
        val path = File(trustPath(ctx))
        return try {
            path.absoluteFile.parentFile.mkdirs()
            path.outputStream().use { buildTruststore(ca, defaultCacerts(), ctx.param("storepass", "changeit").toCharArray(), it) }
            val jvms = ctx.runner.run(listOf("jcmd", "-l"), 5000)
            ActionResult(true, "truststore written: ${path.path}\nUse:\n${jvmArgs(ctx).joinToString(" ")}" +
                (if (jvms.ok) "\n\nRunning JVMs:\n" + parseJcmd(jvms.output).joinToString("\n") { "${it.first} ${it.second}" } else "\n(jcmd unavailable: ${jvms.output.trim()})"))
        } catch (e: Exception) { ActionResult(false, "failed: ${e.message}") }
    }

    override fun undo(ctx: SetupContext): ActionResult {
        val f = File(trustPath(ctx))
        return ActionResult(true, if (f.delete()) "deleted ${f.path}" else "nothing to delete at ${f.path}")
    }
}

/** Chromium-family / Electron flags and a throwaway Chrome/Firefox profile that trusts the CA. */
object BrowserTarget : SetupTarget {
    override val id = "browser"
    override val title = "Chromium / Electron / Firefox"
    override val executable = true
    override val params = listOf(
        ParamSpec("browser", "Browser", "chrome", listOf("chrome", "firefox")),
        ParamSpec("binary", "Executable (blank = auto)"),
        ParamSpec("url", "Start URL", "about:blank"),
    )
    private val chromeCandidates = listOf("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "microsoft-edge")

    fun proxyFlag(ctx: SetupContext): String =
        "--proxy-server=" + (if (ctx.proxyType == "http") "http" else "socks5") + "://${ctx.host}:${ctx.port}"

    fun chromeArgs(ctx: SetupContext, profile: File, spki: String): List<String> = SetupValidation.check(ctx, this).let { listOf(
        proxyFlag(ctx), "--ignore-certificate-errors-spki-list=$spki", "--user-data-dir=${profile.path}",
        "--no-first-run", "--no-default-browser-check", ctx.param("url", "about:blank"),
    ) }

    fun firefoxPrefs(ctx: SetupContext): String {
        SetupValidation.requireHost("host", ctx.host) // interpolated into user.js
        val sb = StringBuilder("user_pref(\"network.proxy.type\", 1);\n")
        if (ctx.proxyType == "http") {
            sb.append("user_pref(\"network.proxy.http\", \"${ctx.host}\");\nuser_pref(\"network.proxy.http_port\", ${ctx.port});\n")
            sb.append("user_pref(\"network.proxy.ssl\", \"${ctx.host}\");\nuser_pref(\"network.proxy.ssl_port\", ${ctx.port});\n")
        } else {
            sb.append("user_pref(\"network.proxy.socks\", \"${ctx.host}\");\nuser_pref(\"network.proxy.socks_port\", ${ctx.port});\n")
            sb.append("user_pref(\"network.proxy.socks_version\", 5);\nuser_pref(\"network.proxy.socks_remote_dns\", true);\n")
        }
        sb.append("user_pref(\"network.proxy.allow_hijacking_localhost\", true);\nuser_pref(\"network.proxy.no_proxies_on\", \"\");\n")
        return sb.toString()
    }

    private fun chromeProfile(ctx: SetupContext) = File(ctx.workDir, "chrome-profile")
    private fun firefoxProfile(ctx: SetupContext) = File(ctx.workDir, "firefox-profile")

    override fun guide(ctx: SetupContext): String {
        val spki = CaInfo.spkiHash(ctx.caCert) ?: "<SPKI hash: CA certificate not readable at ${ctx.caPath}>"
        val bin = ctx.param("binary", "google-chrome")
        return buildString {
            appendLine("# Chromium / Chrome / Edge / any Electron app (temporary profile, CA pinned by SPKI hash)")
            appendLine(Sh.join(listOf(bin) + chromeArgs(ctx, chromeProfile(ctx), spki)))
            appendLine()
            appendLine("# Electron app: pass the same --proxy-server and --ignore-certificate-errors-spki-list flags to the app executable.")
            appendLine("# Note: QUIC/HTTP3 bypasses TCP proxies; add --disable-quic if traffic is missing.")
            appendLine()
            appendLine("# Firefox: dedicated profile trusting the CA (needs NSS 'certutil')")
            val p = firefoxProfile(ctx).path
            appendLine("mkdir -p ${Sh.q(p)}")
            appendLine(Sh.join(listOf("certutil", "-N", "-d", "sql:$p", "--empty-password")))
            appendLine(Sh.join(listOf("certutil", "-A", "-n", "Expedition", "-t", "C,,", "-i", ctx.caPath, "-d", "sql:$p")))
            appendLine("# $p/user.js:")
            appendLine(firefoxPrefs(ctx).trimEnd())
            appendLine(Sh.join(listOf("firefox", "--no-remote", "--profile", p)))
        }
    }

    override fun apply(ctx: SetupContext): ActionResult {
        if (ctx.caCert.canRead().not()) return ActionResult(false, "cannot read CA certificate at ${ctx.caPath}")
        ctx.workDir.mkdirs()
        return if (ctx.param("browser", "chrome") == "firefox") applyFirefox(ctx) else applyChrome(ctx)
    }

    private fun applyChrome(ctx: SetupContext): ActionResult {
        val spki = CaInfo.spkiHash(ctx.caCert) ?: return ActionResult(false, "cannot parse CA certificate")
        val args = chromeArgs(ctx, chromeProfile(ctx).also { it.mkdirs() }, spki)
        val bins = ctx.param("binary").takeIf { it.isNotEmpty() }?.let { listOf(it) } ?: chromeCandidates
        for (b in bins) {
            try {
                ctx.state.stop("browser")
                ctx.state.processes["browser"] = ctx.runner.spawn(listOf(b) + args)
                return ActionResult(true, "started $b with temporary profile ${chromeProfile(ctx).path}")
            } catch (_: java.io.IOException) { /* try next */ }
        }
        return ActionResult(false, "no Chromium-family browser found (tried ${bins.joinToString()}); set 'binary'")
    }

    private fun applyFirefox(ctx: SetupContext): ActionResult {
        val p = firefoxProfile(ctx).also { it.mkdirs() }
        File(p, "user.js").writeText(firefoxPrefs(ctx))
        val log = StringBuilder()
        val n = ctx.runner.run(listOf("certutil", "-N", "-d", "sql:${p.path}", "--empty-password"), 10_000)
        val a = if (n.missing) n else ctx.runner.run(listOf("certutil", "-A", "-n", "Expedition", "-t", "C,,", "-i", ctx.caPath, "-d", "sql:${p.path}"), 10_000)
        if (!a.ok) log.appendLine("warning: CA not imported into Firefox profile (${a.output.trim()}); install NSS 'certutil' or import the CA manually")
        val bin = ctx.param("binary", "firefox")
        return try {
            ctx.state.stop("browser")
            ctx.state.processes["browser"] = ctx.runner.spawn(listOf(bin, "--no-remote", "--profile", p.path, ctx.param("url", "about:blank")))
            ActionResult(a.ok, log.toString() + "started $bin with profile ${p.path}")
        } catch (e: java.io.IOException) { ActionResult(false, log.toString() + "'$bin' not found in PATH") }
    }

    override fun undo(ctx: SetupContext): ActionResult =
        ActionResult(true, if (ctx.state.stop("browser")) "browser process stopped" else "no browser started by Expedition")
}

/**
 * Burp Proxy -> Expedition SOCKS5 chain. Pure instructions: Montoya handlers cannot return
 * synthetic responses, so to apply Expedition's rules engine to Burp Proxy traffic Burp's
 * upstream SOCKS proxy is pointed at an Expedition SOCKS5 listener (TLS MITM).
 */
object BurpChainTarget : SetupTarget {
    override val id = "burp-chain"
    override val title = "Burp Proxy -> Expedition SOCKS chain"
    override val params = listOf(
        ParamSpec("username", "SOCKS username (blank = no auth)"),
        ParamSpec("password", "SOCKS password"),
    )

    override fun guide(ctx: SetupContext): String {
        val user = ctx.param("username")
        val pass = if (user.isEmpty()) "" else ctx.param("password", "<password>")
        val listenerJson = buildString {
            append("""{"name":"burp-chain","protocol":"socks5","bind_host":"${ctx.host}","bind_port":${ctx.port},"tls":"mitm"""")
            if (user.isNotEmpty()) append(""","username":"$user","password":"$pass"""")
            append("}")
        }
        val caDir = ctx.caCert.absoluteFile.parentFile?.path ?: "~/.expedition"
        return buildString {
            appendLine("# Burp Proxy -> Expedition SOCKS5 chain (rules engine on ALL Burp Proxy traffic)")
            appendLine("# Flow: client -> Burp Proxy -> (upstream SOCKS) -> Expedition listener [rules, MITM TLS] -> server")
            appendLine()
            appendLine("## 1. Create the SOCKS5 listener in Expedition (TLS MITM)")
            appendLine("# Either use the Listeners tab (protocol SOCKS5, TLS MITM, bind ${ctx.proxyAddr}) or the control API")
            appendLine("# (start Burp with EXPEDITION_API_ENABLE=1; default API 127.0.0.1:18112).")
            appendLine("# Token: read it from ${Sh.q("$caDir/api-token")} - do NOT paste the real token into notes or tickets.")
            appendLine("curl -s -X POST http://127.0.0.1:18112/listeners \\")
            appendLine("  -H \"Authorization: Bearer \$(cat ${Sh.q("$caDir/api-token")})\" \\")
            appendLine("  -H 'Content-Type: application/json' \\")
            appendLine("  -d ${Sh.q(listenerJson)}")
            appendLine("# Keep bind_host on loopback unless Burp runs on another machine.")
            appendLine()
            appendLine("## 2. Point Burp's upstream at it")
            appendLine("# Burp: Settings -> Network -> Connections -> SOCKS proxy (menu names vary by Burp version)")
            appendLine("#   Use SOCKS proxy : ON")
            appendLine("#   SOCKS proxy host: ${ctx.host}")
            appendLine("#   SOCKS proxy port: ${ctx.port}")
            appendLine("#   Username        : ${user.ifEmpty { "(leave empty)" }}")
            appendLine("#   Password        : ${if (user.isEmpty()) "(leave empty)" else pass}")
            appendLine("#   [x] Do DNS lookups over SOCKS proxy")
            appendLine("# Note: a Burp SOCKS proxy is applied to ALL Burp outbound traffic (Proxy, Repeater, Scanner, ...).")
            appendLine()
            appendLine("## 3. Make Burp trust Expedition's leaf certificates")
            appendLine("# Burp now sees certificates minted by the Expedition CA (${ctx.caPath}), not the origin's.")
            appendLine("# Pick one (exact menu names differ between Burp versions):")
            appendLine("#  a) Settings -> Network -> TLS -> enable the option to allow connections to servers with invalid")
            appendLine("#     certificates (broad; only on a test setup), or use the per-host override if your version has one.")
            appendLine("#  b) Add the CA to the Java truststore Burp runs on, then restart Burp. Easiest: the 'jvm' setup target")
            appendLine("#     builds a truststore (system CAs + Expedition CA); launch Burp with its -Djavax.net.ssl.trustStore flags.")
            appendLine("#     Manual: keytool -importcert -trustcacerts -alias expedition-ca -file ${Sh.q(ctx.caPath)} -keystore <burp-jre>/lib/security/cacerts")
            appendLine("#  c) Settings -> Network -> TLS -> Server TLS certificates: only for client-cert auth, it does NOT add trusted CAs.")
            appendLine("# The browser/client still trusts BURP's CA as usual; Expedition's CA is needed only by Burp itself.")
            appendLine()
            appendLine("## 4. Add rules in Expedition (mock / delay / timeout / RST / redirect / transform) and verify")
            appendLine("# Replace 8080 with your Burp Proxy listener; -k because the client sees Burp's cert.")
            appendLine("curl -sk -i -x http://127.0.0.1:8080 https://example.com/ | head -20")
            appendLine("# Expected: the mocked status/body from your Expedition rule. Check Expedition History for the flow.")
            appendLine("# No effect? Run: curl -sv --socks5-hostname ${ctx.proxyAddr} -k https://example.com/ to test the listener directly.")
            appendLine()
            appendLine("## Honest limitations")
            appendLine("# - Burp sees Expedition's certificate; scope, Scanner and Logger still work, but cert-based findings reflect Expedition, not the origin.")
            appendLine("# - Rules apply to HTTP/1.x only; HTTP/2 passes through as bytes (no rule matching).")
            appendLine("# - A mock is answered by Expedition, but if Burp or the client needs the upstream and the host is dead, expect a 502.")
            appendLine("# - Not verified against every Burp version; menu names and TLS options may differ.")
            appendLine("# Undo: switch off 'Use SOCKS proxy' in Burp and DELETE /listeners/burp-chain.")
        }
    }
}
