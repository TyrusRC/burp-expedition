package expedition.ui

import expedition.dissector.DissectorRegistry
import expedition.engine.ListenerConfig
import expedition.engine.Socks5ListenerConfig
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.session.FlowTagStore
import expedition.tls.BurpCertificateProvider
import javax.swing.JComponent
import javax.swing.JOptionPane
import javax.swing.JTabbedPane

class ExpeditionTab(
    private val registry: ConnectionRegistry,
    private val dissectorRegistry: DissectorRegistry,
    private val matchReplaceEngine: MatchReplaceEngine,
    private val interceptController: InterceptController,
    private val onStartListener: (ListenerConfig) -> Unit,
    private val onStopListener: (String) -> Unit,
    private val onStartSocks5Listener: (Socks5ListenerConfig) -> Unit = {},
    initialCertificateProvider: BurpCertificateProvider? = null,
    private val flowTagStore: FlowTagStore = FlowTagStore(),
    private val scriptHooks: expedition.script.ScriptHooks? = null,
    private val dnsController: expedition.dns.DnsController? = null,
    private val rulesEngine: expedition.rules.RulesEngine? = null,
) {
    private val tabbedPane = JTabbedPane()
    val component: JComponent = tabbedPane

    // Defaults to the auto-generated CA (if any); "Configure CA Keystore" replaces it with Burp's.
    @Volatile
    private var certificateProvider: BurpCertificateProvider? = initialCertificateProvider

    private val interceptPanel = InterceptPanel(interceptController, dissectorRegistry)
    private val historyPanel = HistoryPanel(registry, dissectorRegistry, flowTagStore)
    private val matchReplacePanel = MatchReplacePanel(matchReplaceEngine)

    private lateinit var listenersPanel: ListenersPanel
    private var dnsPanel: DnsPanel? = null

    /** Adds restored listener rows in the stopped state (call on the EDT). */
    fun addRestoredListener(config: ListenerConfig) = listenersPanel.addRestored(config)
    fun addRestoredSocks5Listener(config: Socks5ListenerConfig) = listenersPanel.addRestoredSocks5(config)
    fun populateDns(rules: List<expedition.dns.DnsRedirector.Rule>, defaultIp: String?, port: Int) =
        dnsPanel?.populate(rules, defaultIp, port)

    init {
        listenersPanel = ListenersPanel(
            onStartListener, onStopListener,
            onConfigureCertificateProvider = { provider -> certificateProvider = provider },
            onStartSocks5Listener = onStartSocks5Listener,
            certificateProviderPreconfigured = certificateProvider != null
        )
        tabbedPane.addTab("Listeners", listenersPanel.component)
        tabbedPane.addTab("Intercept", interceptPanel.component)
        tabbedPane.addTab("History", historyPanel.component)
        tabbedPane.addTab("Match & Replace", matchReplacePanel.component)
        if (rulesEngine != null) tabbedPane.addTab("Rules", expedition.rules.RulesPanel(rulesEngine, registry).component)
        tabbedPane.addTab("Setup", SetupPanel().component)
        tabbedPane.addTab("Analysis", expedition.analysis.AnalysisPanel(registry).component)
        if (scriptHooks != null) tabbedPane.addTab("Scripting", ScriptingPanel(scriptHooks).component)
        if (dnsController != null) {
            dnsPanel = DnsPanel(dnsController)
            tabbedPane.addTab("DNS", dnsPanel!!.component)
        }
    }

    fun currentCertificateProvider(): BurpCertificateProvider? = certificateProvider

    fun onHeldMessage(heldMessageId: Long, connectionId: Long, direction: Direction, bytes: ByteArray) {
        interceptPanel.onHeldMessage(heldMessageId, connectionId, direction, bytes)
    }

    fun onListenerError(listenerName: String, message: String) {
        // invokeLater: onError may be called from a Netty/HTTP thread (e.g. the control API).
        // A modal dialog shown off the EDT would block that thread — freezing the API/engine.
        javax.swing.SwingUtilities.invokeLater {
            JOptionPane.showMessageDialog(component, "Listener '$listenerName' failed: $message", "Expedition", JOptionPane.ERROR_MESSAGE)
        }
    }
}
