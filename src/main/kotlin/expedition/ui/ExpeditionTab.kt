package expedition.ui

import expedition.dissector.DissectorRegistry
import expedition.engine.ListenerConfig
import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import expedition.tls.BurpCertificateProvider
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
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

    init {
        val listenersPanel = ListenersPanel(
            onStartListener, onStopListener,
            onConfigureCertificateProvider = { provider -> certificateProvider = provider }
        )
        tabbedPane.addTab("Listeners", listenersPanel.component)
        tabbedPane.addTab("Intercept", placeholderPanel("Intercept UI — added in Task 14"))
        tabbedPane.addTab("History", placeholderPanel("History UI — added in Task 15"))
        tabbedPane.addTab("Match & Replace", placeholderPanel("Match & Replace UI — added in Task 16"))
    }

    private fun placeholderPanel(text: String): JComponent = JPanel().apply { add(JLabel(text)) }

    fun currentCertificateProvider(): BurpCertificateProvider? = certificateProvider

    // Real behavior (populating the Intercept panel's held-message list) is wired in Task 14.
    fun onHeldMessage(heldMessageId: Long, connectionId: Long, direction: Direction, bytes: ByteArray) {
    }

    fun onListenerError(listenerName: String, message: String) {
        JOptionPane.showMessageDialog(component, "Listener '$listenerName' failed: $message", "Expedition", JOptionPane.ERROR_MESSAGE)
    }
}
