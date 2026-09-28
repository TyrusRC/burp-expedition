package expedition.ui

import expedition.dissector.DissectorRegistry
import expedition.engine.ListenerConfig
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
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
    private val onStopListener: (String) -> Unit
) {
    private val tabbedPane = JTabbedPane()
    val component: JComponent = tabbedPane

    @Volatile
    private var certificateProvider: BurpCertificateProvider? = null

    private val interceptPanel = InterceptPanel(interceptController, dissectorRegistry)
    private val historyPanel = HistoryPanel(registry, dissectorRegistry)
    private val matchReplacePanel = MatchReplacePanel(matchReplaceEngine)

    init {
        val listenersPanel = ListenersPanel(
            onStartListener, onStopListener,
            onConfigureCertificateProvider = { provider -> certificateProvider = provider }
        )
        tabbedPane.addTab("Listeners", listenersPanel.component)
        tabbedPane.addTab("Intercept", interceptPanel.component)
        tabbedPane.addTab("History", historyPanel.component)
        tabbedPane.addTab("Match & Replace", matchReplacePanel.component)
    }

    fun currentCertificateProvider(): BurpCertificateProvider? = certificateProvider

    fun onHeldMessage(heldMessageId: Long, connectionId: Long, direction: Direction, bytes: ByteArray) {
        interceptPanel.onHeldMessage(heldMessageId, connectionId, direction, bytes)
    }

    fun onListenerError(listenerName: String, message: String) {
        JOptionPane.showMessageDialog(component, "Listener '$listenerName' failed: $message", "Expedition", JOptionPane.ERROR_MESSAGE)
    }
}
