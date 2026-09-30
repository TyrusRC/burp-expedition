package expedition

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import expedition.engine.ProxyEngine
import expedition.dissector.DissectorRegistry
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.server.ControlApiServer
import expedition.ui.ExpeditionTab

class ExpeditionExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        val registry = ConnectionRegistry()
        val dissectorRegistry = DissectorRegistry()
        // register() inserts at index 0 (last wins), so register lowest-priority first.
        // Protobuf's heuristic is eager and matches only non-text binary, so it sits
        // below Redis and the text dissector: Redis -> text -> Protobuf -> hex default.
        dissectorRegistry.register(expedition.dissector.ProtobufDissector())
        dissectorRegistry.register(expedition.dissector.PostgresDissector())
        dissectorRegistry.register(expedition.dissector.MysqlDissector())
        dissectorRegistry.register(expedition.dissector.MongoDissector())
        dissectorRegistry.register(expedition.dissector.WebSocketDissector())
        dissectorRegistry.register(expedition.dissector.ModbusDissector())
        dissectorRegistry.register(expedition.dissector.Dnp3Dissector())
        dissectorRegistry.register(expedition.dissector.MqttDissector())
        dissectorRegistry.register(expedition.dissector.DnsDissector())
        dissectorRegistry.register(expedition.dissector.LineProtocolDissector())
        dissectorRegistry.register(expedition.dissector.RedisDissector())
        val matchReplaceEngine = MatchReplaceEngine(dissectorRegistry)
        val interceptController = InterceptController()

        // Auto-generate a per-machine default CA so TLS MITM / STARTTLS work out of the box.
        // Disable with EXPEDITION_AUTOCA_DISABLE=1; relocate with EXPEDITION_CA_DIR.
        val defaultCaProvider = if (System.getenv("EXPEDITION_AUTOCA_DISABLE") == "1") null else runCatching {
            val caDir = java.io.File(
                System.getenv("EXPEDITION_CA_DIR")?.takeIf { it.isNotBlank() }
                    ?: (System.getProperty("user.home") + java.io.File.separator + ".expedition")
            )
            val p12 = expedition.tls.DefaultCa.ensureDefaultCa(caDir, "expedition".toCharArray())
            expedition.tls.BurpCertificateProvider(p12, "expedition".toCharArray()).also {
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
            onError = { name, message -> tab.onListenerError(name, message) }
        )
        tab = ExpeditionTab(
            registry, dissectorRegistry, matchReplaceEngine, interceptController,
            onStartListener = { config -> engine.startListener(config) },
            onStopListener = { name -> engine.stopListener(name) },
            onStartSocks5Listener = { config -> engine.startSocks5Listener(config) },
            initialCertificateProvider = defaultCaProvider
        )

        api.userInterface().registerSuiteTab("Expedition", tab.component)

        // Loopback control API (Praetor MCP). Disable with EXPEDITION_API_DISABLE=1;
        // override the port with EXPEDITION_API_PORT (default 18112).
        val apiServer = if (System.getenv("EXPEDITION_API_DISABLE") == "1") null else runCatching {
            // Loopback default (secure). Override with EXPEDITION_API_HOST only
            // when the MCP client is off-host (NAT-mode WSL reaches Burp on the
            // Windows IP) — set it to the reachable bind IP, not 0.0.0.0.
            val bindHost = System.getenv("EXPEDITION_API_HOST")?.takeIf { it.isNotBlank() } ?: "127.0.0.1"
            val port = System.getenv("EXPEDITION_API_PORT")?.toIntOrNull() ?: 18112
            ControlApiServer(
                host = bindHost, port = port,
                registry = registry, matchReplace = matchReplaceEngine,
                intercept = interceptController,
                // API path uses the *Checked variants so a bind failure returns an HTTP
                // error to the caller (curl/Praetor) instead of silently succeeding.
                startListener = { engine.startListenerChecked(it) },
                stopListener = { engine.stopListener(it) },
                runningListeners = { engine.runningListenerNames() },
                startSocks5Listener = { engine.startSocks5ListenerChecked(it) },
            ).also {
                it.start()
                api.logging().logToOutput("Expedition control API on $bindHost:$port")
                if (it.isExposedBeyondLoopback()) api.logging().logToError(
                    "WARNING: Expedition control API is bound to a NON-loopback host " +
                    "($bindHost) — it can start proxies and send arbitrary bytes. " +
                    "Ensure the interface is trusted / firewalled; prefer loopback + " +
                    "WSL mirrored networking where possible.")
            }
        }.onFailure { api.logging().logToError("Expedition control API failed to start: ${it.message}") }.getOrNull()

        api.extension().registerUnloadingHandler(ExtensionUnloadingHandler {
            apiServer?.stop()
            engine.shutdown()
        })
    }
}
