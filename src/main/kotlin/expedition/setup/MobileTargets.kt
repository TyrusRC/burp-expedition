package expedition.setup

import java.io.File

/** Android over ADB: CA install (user/system), adb reverse, global proxy, undo. */
object AdbTarget : SetupTarget {
    override val id = "adb"
    override val title = "Android (ADB)"
    override val executable = true
    override val params = listOf(
        ParamSpec("serial", "Device serial (blank = only device)"),
        ParamSpec("reverse", "Use adb reverse (device sees 127.0.0.1)", "yes", listOf("yes", "no")),
        ParamSpec("device_host", "Proxy host as seen by device (when reverse=no)", "10.0.2.2"),
        ParamSpec("system_ca", "Install into system store (rooted/emulator)", "no", listOf("no", "yes")),
    )
    const val DEVICE_CA = "/sdcard/Download/expedition-ca.crt"

    private fun adb(ctx: SetupContext, vararg a: String): List<String> {
        val s = ctx.param("serial")
        return listOf("adb") + (if (s.isEmpty()) emptyList() else listOf("-s", s)) + a
    }

    fun deviceProxy(ctx: SetupContext): String =
        if (ctx.param("reverse", "yes") == "yes") "127.0.0.1:${ctx.port}" else "${ctx.param("device_host", "10.0.2.2")}:${ctx.port}"

    /** Commands for the apply step (argv lists). Pure. */
    fun applyCommands(ctx: SetupContext): List<List<String>> {
        SetupValidation.check(ctx, this) // values reach `adb shell`, which re-joins argv into a device shell line
        val c = mutableListOf<List<String>>()
        c += adb(ctx, "push", ctx.caPath, DEVICE_CA)
        if (ctx.param("reverse", "yes") == "yes") c += adb(ctx, "reverse", "tcp:${ctx.port}", "tcp:${ctx.port}")
        if (ctx.proxyType == "http") c += adb(ctx, "shell", "settings", "put", "global", "http_proxy", deviceProxy(ctx))
        return c
    }

    fun undoCommands(ctx: SetupContext): List<List<String>> = buildList {
        SetupValidation.check(ctx, this@AdbTarget)
        add(adb(ctx, "shell", "settings", "put", "global", "http_proxy", ":0"))
        add(adb(ctx, "reverse", "--remove", "tcp:${ctx.port}"))
        add(adb(ctx, "shell", "rm", "-f", DEVICE_CA))
    }

    override fun guide(ctx: SetupContext): String {
        val ca = ctx.caPath
        return buildString {
            appendLine("# 1. Check the device")
            appendLine(Sh.join(adb(ctx, "devices", "-l")))
            appendLine()
            appendLine("# 2. Reach the host listener from the device")
            if (ctx.param("reverse", "yes") == "yes") appendLine(Sh.join(adb(ctx, "reverse", "tcp:${ctx.port}", "tcp:${ctx.port}")))
            else appendLine("# no reverse: device uses ${deviceProxy(ctx)} (emulator: 10.0.2.2 = host; real device: host LAN IP, listener bound to 0.0.0.0)")
            appendLine()
            appendLine("# 3. Proxy")
            if (ctx.proxyType == "http") appendLine(Sh.join(adb(ctx, "shell", "settings", "put", "global", "http_proxy", deviceProxy(ctx))))
            else appendLine("# Android's global proxy is HTTP-only; for the SOCKS5 listener use an app-level SOCKS client (ProxyDroid, per-app VPN) or iptables REDIRECT, or chain through an HTTP listener.")
            appendLine()
            appendLine("# 4a. User CA (works for apps trusting user CAs; Android 7+ apps usually do NOT, see 4b/Frida)")
            appendLine(Sh.join(adb(ctx, "push", ca, DEVICE_CA)))
            appendLine("# then: Settings > Security > Encryption & credentials > Install a certificate > CA certificate > expedition-ca.crt")
            appendLine()
            appendLine("# 4b. System CA (root / emulator with -writable-system). <hash> = output of the first command")
            appendLine("HASH=\$(openssl x509 -inform PEM -subject_hash_old -in ${Sh.q(ca)} -noout)")
            appendLine("cp ${Sh.q(ca)} \"\$HASH.0\"")
            appendLine(Sh.join(adb(ctx, "root")))
            appendLine(Sh.join(adb(ctx, "remount")))
            appendLine(Sh.join(adb(ctx, "push", "\$HASH.0", "/system/etc/security/cacerts/")).replace("'\$HASH.0'", "\"\$HASH.0\""))
            appendLine(Sh.join(adb(ctx, "shell", "chmod", "644", "/system/etc/security/cacerts/\$HASH.0")).replace("'/system/etc/security/cacerts/\$HASH.0'", "\"/system/etc/security/cacerts/\$HASH.0\""))
            appendLine(Sh.join(adb(ctx, "reboot")))
            appendLine("# Android 14+: the store lives in /apex/com.android.conscrypt/cacerts (read-only). Copy it to a tmpfs, add the cert, bind-mount over it (as root):")
            appendLine("#   mkdir -p -m 700 /data/local/tmp/certs && cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/certs/ && cp \$HASH.0 /data/local/tmp/certs/")
            appendLine("#   mount -o bind /data/local/tmp/certs /apex/com.android.conscrypt/cacerts   (repeat in zygote's namespace or restart apps)")
            appendLine()
            appendLine("# Undo")
            undoCommands(ctx).forEach { appendLine(Sh.join(it)) }
            appendLine("# and remove the certificate from Settings > Security > Trusted credentials > User (or delete \$HASH.0 from the system store)")
        }
    }

    override fun apply(ctx: SetupContext): ActionResult {
        if (!File(ctx.caPath).canRead()) return ActionResult(false, "cannot read CA certificate at ${ctx.caPath}")
        val devs = ctx.runner.run(adb(ctx, "devices"), 10_000)
        if (devs.missing) return ActionResult(false, "adb not found. Install Android platform-tools and add it to PATH.")
        val online = devs.output.lines().drop(1).count { it.trim().endsWith("\tdevice") || it.trim().endsWith(" device") }
        if (!devs.ok || online == 0) return ActionResult(false, "no authorized device:\n${devs.output.trim()}")
        val log = StringBuilder()
        var ok = true
        for (cmd in applyCommands(ctx)) {
            val r = ctx.runner.run(cmd, 20_000)
            log.appendLine("$ ${Sh.join(cmd)}\n${r.output.trim()}")
            if (!r.ok) { ok = false; log.appendLine("FAILED"); break }
        }
        if (ok) log.appendLine("CA pushed to $DEVICE_CA - finish installation in Settings (or use system_ca steps from the guide).")
        return ActionResult(ok, log.toString())
    }

    override fun undo(ctx: SetupContext): ActionResult {
        val log = StringBuilder()
        var ok = true
        for (cmd in undoCommands(ctx)) {
            val r = ctx.runner.run(cmd, 15_000)
            log.appendLine("$ ${Sh.join(cmd)}\n${r.output.trim()}")
            if (r.missing) { ok = false; break }
        }
        return ActionResult(ok, log.toString())
    }
}

/** Frida SSL-unpinning for Android and iOS (experimental). */
object FridaTarget : SetupTarget {
    override val id = "frida"
    override val title = "Frida unpinning (Android / iOS, experimental)"
    override val executable = true
    override val params = listOf(
        ParamSpec("package", "Package / bundle id", "com.example.app"),
        ParamSpec("device", "Device", "usb", listOf("usb", "remote")),
        ParamSpec("remote_host", "frida-server host:port (device=remote)", "127.0.0.1:27042"),
    )

    /** Compact, best-effort unpinning script. Pinning implementations vary; expect to need app-specific tweaks. */
    val UNPIN_JS: String = """
        // Expedition SSL unpinning - EXPERIMENTAL, best effort.
        function tryHook(label, fn) { try { fn(); send('[unpin] ' + label); } catch (e) { console.log('[unpin] skip ' + label + ': ' + e); } }
        if (typeof Java !== 'undefined' && Java.available) {
          Java.perform(function () {
            tryHook('TrustManagerImpl.verifyChain', function () {
              var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
              TMI.verifyChain.implementation = function (chain, root, host, clientAuth, ocsp, tls) { return chain; };
            });
            tryHook('X509TrustManager (custom, accept all)', function () {
              var X509 = Java.use('javax.net.ssl.X509TrustManager');
              var TM = Java.registerClass({ name: 'org.expedition.TrustAll', implements: [X509], methods: {
                checkClientTrusted: function (c, a) {}, checkServerTrusted: function (c, a) {}, getAcceptedIssuers: function () { return []; } } });
              var SSLContext = Java.use('javax.net.ssl.SSLContext');
              var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
              init.implementation = function (km, tm, sr) { init.call(this, km, [TM.${'$'}new()], sr); };
            });
            tryHook('OkHttp3 CertificatePinner.check', function () {
              var CP = Java.use('okhttp3.CertificatePinner');
              CP.check.overload('java.lang.String', 'java.util.List').implementation = function (h, p) {};
              try { CP.check${'$'}okhttp.implementation = function (h, f) {}; } catch (e) {}
            });
            tryHook('HttpsURLConnection verifier', function () {
              var H = Java.use('javax.net.ssl.HttpsURLConnection');
              H.setDefaultHostnameVerifier.implementation = function (v) {};
              H.setSSLSocketFactory.implementation = function (f) {};
              H.setHostnameVerifier.implementation = function (v) {};
            });
          });
        }
        if (typeof ObjC !== 'undefined' && ObjC.available) {
          tryHook('SecTrustEvaluate', function () {
            var f = Module.findExportByName('Security', 'SecTrustEvaluate');
            Interceptor.replace(f, new NativeCallback(function (trust, result) { Memory.writeU32(result, 1); return 0; }, 'int', ['pointer', 'pointer']));
          });
          tryHook('SecTrustEvaluateWithError', function () {
            var f = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
            Interceptor.replace(f, new NativeCallback(function (trust, err) { return 1; }, 'bool', ['pointer', 'pointer']));
          });
          tryHook('NSURLSession didReceiveChallenge', function () {
            var cls = ObjC.classes.NSURLSession;
            Interceptor.attach(cls['- dataTaskWithRequest:completionHandler:'].implementation, { onEnter: function () {} });
            var ch = ObjC.classes.NSURLCredential;
            var cred = ch['+ credentialForTrust:'];
            // Delegates that call credentialForTrust: get a credential for the (untrusted) server trust.
            Interceptor.attach(cred.implementation, { onEnter: function () {} });
          });
        }
    """.trimIndent()

    fun scriptFile(ctx: SetupContext) = File(ctx.workDir, "expedition-unpin.js")

    fun fridaArgs(ctx: SetupContext, script: File): List<String> {
        SetupValidation.check(ctx, this)
        val dev = if (ctx.param("device", "usb") == "remote") listOf("-H", ctx.param("remote_host", "127.0.0.1:27042")) else listOf("-U")
        return listOf("frida") + dev + listOf("-f", ctx.param("package", "com.example.app"), "-l", script.path)
    }

    override fun guide(ctx: SetupContext): String = buildString {
        appendLine("# EXPERIMENTAL: generic unpinning only covers common stacks (Conscrypt, OkHttp, HttpsURLConnection, SecTrust*).")
        appendLine("# Prerequisites: frida-tools on host (pip install frida-tools), frida-server (Android, root) or frida-gadget/jailbroken iOS on the device,")
        appendLine("# and the app's traffic routed to Expedition (see the ADB target; iOS: set the Wi-Fi HTTP proxy to the host).")
        appendLine("# Save the script below as ${scriptFile(ctx).path}, then run:")
        appendLine(Sh.join(fridaArgs(ctx, scriptFile(ctx))))
        appendLine("# Attach to a running app instead:  frida ${if (ctx.param("device", "usb") == "remote") "-H ${ctx.param("remote_host", "127.0.0.1:27042")}" else "-U"} -n <process> -l ${Sh.q(scriptFile(ctx).path)}")
        appendLine()
        appendLine("// ---- expedition-unpin.js ----")
        appendLine(UNPIN_JS)
    }

    override fun apply(ctx: SetupContext): ActionResult {
        val v = ctx.runner.run(listOf("frida", "--version"), 10_000)
        if (v.missing) return ActionResult(false, "frida not found. Install with: pip install frida-tools")
        return try {
            ctx.workDir.mkdirs()
            val f = scriptFile(ctx).also { it.writeText(UNPIN_JS) }
            ctx.state.stop("frida")
            ctx.state.processes["frida"] = ctx.runner.spawn(fridaArgs(ctx, f))
            ActionResult(true, "frida ${v.output.trim()} started for ${ctx.param("package", "com.example.app")} with ${f.path} (experimental)")
        } catch (e: java.io.IOException) { ActionResult(false, "failed to start frida: ${e.message}") }
    }

    override fun undo(ctx: SetupContext): ActionResult =
        ActionResult(true, if (ctx.state.stop("frida")) "frida stopped" else "no frida session started by Expedition")
}
