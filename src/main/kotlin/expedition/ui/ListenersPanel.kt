package expedition.ui

import expedition.engine.ListenerConfig
import expedition.engine.TlsMode
import expedition.registry.Protocol
import expedition.tls.BurpCertificateProvider
import java.awt.BorderLayout
import java.awt.GridLayout
import javax.swing.*

class ListenersPanel(
    private val onStartListener: (ListenerConfig) -> Unit,
    private val onStopListener: (String) -> Unit,
    private val onConfigureCertificateProvider: (BurpCertificateProvider) -> Unit
) {
    private val tableModel = ListenerTableModel()
    private val table = JTable(tableModel)
    @Volatile private var certificateProviderConfigured = false
    val component: JComponent

    init {
        val addButton = JButton("Add Listener").apply { addActionListener { showAddDialog() } }
        val stopButton = JButton("Stop Selected").apply { addActionListener { stopSelected() } }
        val caButton = JButton("Configure CA Keystore...").apply { addActionListener { showCaDialog() } }
        val buttonPanel = JPanel().apply { add(addButton); add(stopButton); add(caButton) }
        component = JPanel(BorderLayout()).apply {
            add(JScrollPane(table), BorderLayout.CENTER)
            add(buttonPanel, BorderLayout.SOUTH)
        }
    }

    private fun showCaDialog() {
        val chooser = JFileChooser()
        chooser.dialogTitle = "Select Burp CA PKCS#12 keystore (exported from Burp → Proxy → Certificate settings)"
        if (chooser.showOpenDialog(component) != JFileChooser.APPROVE_OPTION) return

        val passwordField = JPasswordField()
        val form = JPanel(GridLayout(0, 1)).apply {
            add(JLabel("Keystore password"))
            add(passwordField)
        }
        val result = JOptionPane.showConfirmDialog(component, form, "Configure CA Keystore", JOptionPane.OK_CANCEL_OPTION)
        if (result != JOptionPane.OK_OPTION) return

        try {
            val provider = BurpCertificateProvider(chooser.selectedFile, passwordField.password)
            onConfigureCertificateProvider(provider)
            certificateProviderConfigured = true
            JOptionPane.showMessageDialog(component, "CA keystore loaded successfully.")
        } catch (e: Exception) {
            // Review Focus item 3: a missing/invalid keystore must fail loudly here,
            // never silently leave TLS MITM listeners unconfigured without telling the user.
            JOptionPane.showMessageDialog(component, "Failed to load keystore: ${e.message}", "Invalid keystore", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun showAddDialog() {
        val nameField = JTextField()
        val protocolBox = JComboBox(Protocol.values())
        val bindHostField = JTextField("127.0.0.1")
        val bindPortField = JTextField()
        val upstreamHostField = JTextField()
        val upstreamPortField = JTextField()
        val tlsBox = JComboBox(TlsMode.values())

        val form = JPanel(GridLayout(0, 2)).apply {
            add(JLabel("Name")); add(nameField)
            add(JLabel("Protocol")); add(protocolBox)
            add(JLabel("Bind host")); add(bindHostField)
            add(JLabel("Bind port")); add(bindPortField)
            add(JLabel("Upstream host")); add(upstreamHostField)
            add(JLabel("Upstream port")); add(upstreamPortField)
            add(JLabel("TLS mode")); add(tlsBox)
        }

        val result = JOptionPane.showConfirmDialog(component, form, "Add Listener", JOptionPane.OK_CANCEL_OPTION)
        if (result != JOptionPane.OK_OPTION) return

        val validated = ListenerFormValidation.validate(
            nameField.text, protocolBox.selectedItem as Protocol, bindHostField.text, bindPortField.text,
            upstreamHostField.text, upstreamPortField.text, tlsBox.selectedItem as TlsMode, tableModel.names(),
            certificateProviderConfigured
        )
        validated.onSuccess { config ->
            tableModel.add(config)
            onStartListener(config)
        }.onFailure { error ->
            JOptionPane.showMessageDialog(component, error.message, "Invalid listener", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun stopSelected() {
        val row = table.selectedRow
        if (row < 0) return
        val config = tableModel.at(row)
        onStopListener(config.name)
        tableModel.remove(row)
    }
}
