package expedition

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import expedition.engine.ProxyEngine
import expedition.dissector.DissectorRegistry
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.ui.ExpeditionTab

class ExpeditionExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        val registry = ConnectionRegistry()
        val dissectorRegistry = DissectorRegistry()
        val matchReplaceEngine = MatchReplaceEngine()
        val interceptController = InterceptController()

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
            onStopListener = { name -> engine.stopListener(name) }
        )

        api.userInterface().registerSuiteTab("Expedition", tab.component)
        api.extension().registerUnloadingHandler(ExtensionUnloadingHandler { engine.shutdown() })
    }
}
