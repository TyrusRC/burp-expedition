package expedition

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import expedition.engine.ProxyEngine
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.server.ControlApiServer
import expedition.ui.ExpeditionTab

class ExpeditionExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp Expedition v${BuildInfo.VERSION}")
        val registry = ConnectionRegistry()
        // Single source of truth for the dissector line-up and its priority order,
        // kept testable in expedition.dissector.defaultDissectors (DefaultDissectorsTest).
        val dissectorRegistry = expedition.dissector.defaultDissectors()
        val matchReplaceEngine = MatchReplaceEngine(dissectorRegistry)
        val interceptController = InterceptController()
        val rulesEngine = expedition.rules.RulesEngine() // declarative HTTP rules (empty = no effect)
        val flowTagStore = expedition.session.FlowTagStore()
        // Operator scripting hook (JSR-223). Engine is discovered from the host classpath
        // (whatever JSR-223 engine is present); a no-op if none is. See ScriptHooks for the trust model.
        val scriptHooks = expedition.script.ScriptHooks()
        if (scriptHooks.engineAvailable)
            api.logging().logToOutput("Expedition: scripting available (JSR-223 engine discovered).")
        // DNS redirector (spoofing resolver). Owned here so the unload handler can stop it.
        val dnsController = expedition.dns.DnsController(
            onError = { msg -> api.logging().logToError("Expedition DNS: $msg") })

        // Auto-generate a per-machine default CA so TLS MITM / STARTTLS work out of the box.
        // Disable with EXPEDITION_AUTOCA_DISABLE=1; relocate with EXPEDITION_CA_DIR; set the keystore
        // password with EXPEDITION_CA_PASSWORD (otherwise a random one is stored owner-only beside the CA).
        val defaultCaProvider = if (System.getenv("EXPEDITION_AUTOCA_DISABLE") == "1") null else runCatching {
            val caDir = java.io.File(
                System.getenv("EXPEDITION_CA_DIR")?.takeIf { it.isNotBlank() }
                    ?: (System.getProperty("user.home") + java.io.File.separator + ".expedition")
            )
            val caPassword = expedition.tls.DefaultCa.resolvePassword(caDir, System.getenv("EXPEDITION_CA_PASSWORD"))
            val p12 = expedition.tls.DefaultCa.ensureDefaultCa(caDir, caPassword)
            expedition.tls.BurpCertificateProvider(p12, caPassword).also {
                api.logging().logToOutput(
                    "Expedition: using auto-generated CA at ${p12.path} — install " +
                    "${java.io.File(caDir, "expedition-ca.crt").path} in clients, or load Burp's own CA " +
                    "via the Listeners tab to reuse Burp's trust.")
            }
        }.onFailure { api.logging().logToError("Expedition auto-CA failed: ${it.message}") }.getOrNull()

        lateinit var tab: ExpeditionTab
        val engine = ProxyEngine(
            registry, interceptController, matchReplaceEngine,
            certificateProviderSupplier = { tab.currentCertificateProvider() },
            onHeldMessage = { id, connId, direction, bytes -> tab.onHeldMessage(id, connId, direction, bytes) },
            onError = { name, message -> tab.onListenerError(name, message) },
            scriptHooks = scriptHooks,
            rulesEngine = rulesEngine,
        )
        // Configuration persistence (extension data inside the Burp project; see ConfigPersistence).
        // Rules and script are restored BEFORE the tab exists so its tables/editor start populated.
        val persistence = expedition.session.ConfigPersistence(
            store = burpConfigStore(api),
            rules = { matchReplaceEngine.rules() },
            // A restored-but-unapplied script is kept so saving does not silently drop it.
            script = { scriptHooks.source ?: scriptHooks.pendingSource },
            runningNames = { engine.runningListenerNames() },
            log = { api.logging().logToOutput("Expedition: $it") },
            httpRules = { rulesEngine.rules() },
        )
        // Untrusted-project safety: restore never runs a script or binds a socket.
        val restored = runCatching { persistence.loadForRestore().config }
            .onFailure { api.logging().logToError("Expedition: config restore failed: ${it.message}") }
            .getOrDefault(expedition.session.SavedConfig())
        restored.rules.forEach { rule ->
            runCatching { matchReplaceEngine.addRule(rule) }
                .onFailure { api.logging().logToError("Expedition: could not restore rule ${rule.id}: ${it.message}") }
        }
        restored.httpRules.forEach { rule ->
            runCatching { rulesEngine.add(rule) }
                .onFailure { api.logging().logToError("Expedition: could not restore HTTP rule '${rule.name}': ${it.message}") }
        }
        val restoredRuleCount = restored.rules.size + restored.httpRules.size
        expedition.rules.RulesUi.restoreNotice = expedition.rules.RulesUi.restoreNoticeText(restoredRuleCount)
        if (restoredRuleCount > 0) {
            api.logging().logToOutput("Expedition: $restoredRuleCount rules restored disabled — review and enable.")
        }
        restored.script?.let { src ->
            scriptHooks.restorePending(src)
            api.logging().logToOutput("Expedition: a script was restored from the project but NOT applied - review it in the Scripting tab.")
        }
        tab = ExpeditionTab(
            registry, dissectorRegistry, matchReplaceEngine, interceptController,
            onStartListener = { config ->
                persistence.trackListener(config); engine.startListener(config); persistence.save()
            },
            // UI "Stop" also removes the row, so the listener is forgotten (not restored next time).
            onStopListener = { name -> engine.stopListener(name); persistence.forgetListener(name); persistence.save() },
            onStartSocks5Listener = { config ->
                persistence.trackSocks5(config); engine.startSocks5Listener(config); persistence.save()
            },
            initialCertificateProvider = defaultCaProvider,
            flowTagStore = flowTagStore,
            scriptHooks = scriptHooks,
            dnsController = dnsController,
            rulesEngine = rulesEngine,
        )

        api.userInterface().registerSuiteTab("Expedition", tab.component)

        // Restore listeners as STOPPED rows (the operator clicks Start; nothing is bound on load) and DNS form.
        javax.swing.SwingUtilities.invokeLater {
            restored.listeners.forEach { tab.addRestoredListener(it.config) }
            restored.socks5Listeners.forEach { tab.addRestoredSocks5Listener(it.config) }
            restored.dns?.let { tab.populateDns(it.rules, it.defaultIp, it.port) }
        }
        matchReplaceEngine.onChange = { persistence.save() }
        scriptHooks.onChange = { persistence.save() }
        rulesEngine.onChange = { persistence.save() }
        dnsController.onChange = { _, port, rules, defaultIp ->
            persistence.setDns(expedition.session.DnsSettings(rules, defaultIp, port)); persistence.save()
        }
        persistence.save()

        // Loopback control API (MCP). OPT-IN: a Burp extension should not open a
        // listening socket on load unless the operator asks for it, so this stays off
        // unless EXPEDITION_API_ENABLE=1. Override the port with EXPEDITION_API_PORT
        // (default 18112). (EXPEDITION_API_DISABLE is still honoured as a kill switch.)
        val apiEnabled = System.getenv("EXPEDITION_API_ENABLE") == "1" &&
            System.getenv("EXPEDITION_API_DISABLE") != "1"
        val apiServer = if (!apiEnabled) null else runCatching {
            // Loopback default (secure). Override with EXPEDITION_API_HOST only
            // when the MCP client is off-host (NAT-mode WSL reaches Burp on the
            // Windows IP) — set it to the reachable bind IP, not 0.0.0.0.
            val bindHost = System.getenv("EXPEDITION_API_HOST")?.takeIf { it.isNotBlank() } ?: "127.0.0.1"
            val port = System.getenv("EXPEDITION_API_PORT")?.toIntOrNull() ?: 18112
            // Mandatory bearer token: EXPEDITION_API_TOKEN, else a random one persisted owner-only
            // (0600) in ~/.expedition/api-token. A non-loopback bind requires the explicit env token.
            val dataDir = expedition.server.PathSandbox.defaultBase()
            val resolved = expedition.server.ApiToken.resolve(System.getenv("EXPEDITION_API_TOKEN"), dataDir)
            require(ControlApiServer.isLoopback(bindHost) || resolved.explicit) {
                "EXPEDITION_API_HOST=$bindHost is not loopback; set EXPEDITION_API_TOKEN explicitly to expose the API"
            }
            ControlApiServer(
                host = bindHost, port = port,
                registry = registry, matchReplace = matchReplaceEngine,
                intercept = interceptController,
                startListener = { engine.startListenerChecked(it); persistence.trackListener(it); persistence.save() },
                stopListener = { engine.stopListener(it); persistence.save() },
                runningListeners = { engine.runningListenerNames() },
                startSocks5Listener = { engine.startSocks5ListenerChecked(it); persistence.trackSocks5(it); persistence.save() },
                flowTagStore = flowTagStore,
                scriptHooks = scriptHooks,
                dnsController = dnsController,
                authToken = resolved.token,
                tokenExplicit = resolved.explicit,
                rulesEngine = rulesEngine,
                dataDir = dataDir,
            ).also {
                it.start()
                api.logging().logToOutput(
                    "Expedition control API on $bindHost:$port - send 'Authorization: Bearer <token>'; token " +
                    (resolved.file?.let { f -> "stored in ${f.path} (owner-only)" } ?: "from EXPEDITION_API_TOKEN") +
                    ". File paths given to the API are confined to ${dataDir.path}.")
                if (it.isExposedBeyondLoopback()) api.logging().logToError(
                    "WARNING: Expedition control API is bound to a NON-loopback host " +
                    "($bindHost) — it can start proxies and send arbitrary bytes." +
                    " Ensure the interface is trusted / firewalled; prefer loopback + " +
                    "WSL mirrored networking where possible.")
            }
        }.onFailure { api.logging().logToError("Expedition control API failed to start: ${it.message}") }.getOrNull()

        api.extension().registerUnloadingHandler(ExtensionUnloadingHandler {
            persistence.save() // before shutdown, so listeners are saved with their running flag
            apiServer?.stop()
            dnsController.stop()
            engine.shutdown()
        })
    }

    /** Adapts Burp's per-project extension data to the Burp-free [expedition.session.ConfigStore]. */
    private fun burpConfigStore(api: MontoyaApi): expedition.session.ConfigStore {
        val data = api.persistence().extensionData()
        return object : expedition.session.ConfigStore {
            override fun get(key: String): String? = data.getString(key)
            override fun set(key: String, value: String?) {
                if (value == null) data.deleteString(key) else data.setString(key, value)
            }
        }
    }
}
