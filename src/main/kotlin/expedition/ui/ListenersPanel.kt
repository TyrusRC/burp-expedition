package expedition.ui

import expedition.engine.ListenerConfig
import expedition.engine.Socks5ListenerConfig
import expedition.engine.TlsMode
import expedition.registry.Protocol
import expedition.tls.BurpCertificateProvider
import java.awt.BorderLayout
import java.awt.GridLayout
import javax.swing.*

class ListenersPanel(
    private val onStartListener: (ListenerConfig) -> Unit,
    private val onStopListener: (String) -> Unit,
    private val onConfigureCertificateProvider: (BurpCertificateProvider) -> Unit,
    private val onStartSocks5Listener: (Socks5ListenerConfig) -> Unit = {},
    certificateProviderPreconfigured: Boolean = false
) {
    private val tableModel = ListenerTableModel()
    private val table = JTable(tableModel)
    // True once a CA is available — either the auto-generated default or one loaded via the UI.
    @Volatile private var certificateProviderConfigured = certificateProviderPreconfigured
    val component: JComponent

    init {
        val addButton = JButton("Add Listener").apply { addActionListener { showAddDialog() } }
        val stopButton = JButton("Stop Selected").apply { addActionListener { stopSelected() } }
        val startButton = JButton("Start Selected").apply { addActionListener { startSelected() } }
        val caButton = JButton("Configure CA Keystore...").apply { addActionListener { showCaDialog() } }
        val buttonPanel = JPanel().apply { add(addButton); add(startButton); add(stopButton); add(caButton) }
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
        val socksBox = JCheckBox("SOCKS5 dynamic (relays to the client-negotiated destination; ignores upstream)")
        val bindHostField = JTextField("127.0.0.1")
        val bindPortField = JTextField()
        val upstreamHostField = JTextField()
        val upstreamPortField = JTextField()
        val tlsBox = JComboBox(TlsMode.values())
        val upstreamProxyField = JTextField()
        val clientCertField = JTextField()
        val clientCertPwd = JPasswordField()
        val framingBox = JComboBox(arrayOf("Passthrough", "LengthPrefix", "Delimiter"))
        val lenOffsetField = JTextField("0")
        val lenSizeField = JTextField("4")
        val littleEndianBox = JCheckBox("little-endian")
        val lenAdjField = JTextField("0")
        val delimField = JTextField()
        val maxFrameField = JTextField()
        val passthroughField = JTextField()
        val socksUserField = JTextField()
        val socksPwdField = JPasswordField()
        delimField.putClientProperty("JTextField.placeholderText", "e.g. \\r\\n (Delimiter framing)")
        passthroughField.putClientProperty("JTextField.placeholderText", "MITM: host, *.suffix (comma separated)")
        socksUserField.putClientProperty("JTextField.placeholderText", "SOCKS5 only (optional)")

        // Placeholder hints (FlatLaf, which Burp uses, renders these as grey text when empty).
        nameField.putClientProperty("JTextField.placeholderText", "e.g. redis-proxy")
        bindHostField.putClientProperty("JTextField.placeholderText", "127.0.0.1")
        bindPortField.putClientProperty("JTextField.placeholderText", "e.g. 8080")
        upstreamHostField.putClientProperty("JTextField.placeholderText", "e.g. 10.0.0.5 or example.test")
        upstreamPortField.putClientProperty("JTextField.placeholderText", "e.g. 6379")
        upstreamProxyField.putClientProperty("JTextField.placeholderText", "host:port (optional)")
        clientCertField.putClientProperty("JTextField.placeholderText", "/path/to/client.p12 (optional)")
        clientCertPwd.putClientProperty("JTextField.placeholderText", "(optional)")

        val form = JPanel(GridLayout(0, 2)).apply {
            add(JLabel("Name")); add(nameField)
            add(JLabel("SOCKS5")); add(socksBox)
            add(JLabel("Protocol")); add(protocolBox)
            add(JLabel("Bind host")); add(bindHostField)
            add(JLabel("Bind port")); add(bindPortField)
            add(JLabel("Upstream host")); add(upstreamHostField)
            add(JLabel("Upstream port")); add(upstreamPortField)
            add(JLabel("TLS mode")); add(tlsBox)
            add(JLabel("Upstream proxy (host:port)")); add(upstreamProxyField)
            add(JLabel("Upstream client cert (.p12)")); add(clientCertField)
            add(JLabel("Client cert password")); add(clientCertPwd)
            add(JLabel("TCP framing")); add(framingBox)
            add(JLabel("Length offset / size")); add(JPanel(GridLayout(1, 2)).apply { add(lenOffsetField); add(lenSizeField) })
            add(JLabel("Length byte order")); add(littleEndianBox)
            add(JLabel("Length adjustment")); add(lenAdjField)
            add(JLabel("Delimiter")); add(delimField)
            add(JLabel("Max frame bytes")); add(maxFrameField)
            add(JLabel("TLS passthrough (SNI)")); add(passthroughField)
            add(JLabel("SOCKS5 username")); add(socksUserField)
            add(JLabel("SOCKS5 password")); add(socksPwdField)
        }

        val result = JOptionPane.showConfirmDialog(component, form, "Add Listener", JOptionPane.OK_CANCEL_OPTION)
        if (result != JOptionPane.OK_OPTION) return

        ListenerFormValidation.nonLoopbackWarning(bindHostField.text)?.let { warning ->
            val ok = JOptionPane.showConfirmDialog(component, warning, "Non-loopback bind", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE)
            if (ok != JOptionPane.YES_OPTION) return
        }

        if (socksBox.isSelected) {
            addSocks5(
                nameField.text.trim(), bindHostField.text.trim(), bindPortField.text.trim(), tlsBox.selectedItem as TlsMode,
                passthroughField.text, socksUserField.text, String(socksPwdField.password)
            )
            return
        }

        val validated = ListenerFormValidation.validate(
            nameField.text, protocolBox.selectedItem as Protocol, bindHostField.text, bindPortField.text,
            upstreamHostField.text, upstreamPortField.text, tlsBox.selectedItem as TlsMode, tableModel.names(),
            certificateProviderConfigured,
            upstreamProxy = upstreamProxyField.text.trim(),
            clientCertPath = clientCertField.text.trim(),
            clientCertPassword = clientCertPwd.password,
            framing = FramingForm(
                framingBox.selectedItem as String, lenOffsetField.text, lenSizeField.text, !littleEndianBox.isSelected,
                lenAdjField.text, delimField.text, maxFrameField.text
            ),
            tlsPassthrough = passthroughField.text
        )
        validated.onSuccess { config ->
            tableModel.add(config)
            onStartListener(config)
        }.onFailure { error ->
            JOptionPane.showMessageDialog(component, error.message, "Invalid listener", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun addSocks5(name: String, bindHost: String, bindPort: String, tls: TlsMode, passthrough: String, user: String, pwd: String) {
        ListenerFormValidation.validateSocks5(name, bindHost, bindPort, tls, tableModel.names(), certificateProviderConfigured, passthrough, user, pwd)
            .onSuccess { socksConfig ->
                // Cosmetic row: SOCKS5 has no fixed upstream (destinations are negotiated per-connection).
                tableModel.add(ListenerConfig(name, Protocol.TCP, socksConfig.bindHost, socksConfig.bindPort, "(socks5 dynamic)", socksConfig.bindPort))
                socksByName[name] = socksConfig
                onStartSocks5Listener(socksConfig)
            }.onFailure { e ->
                JOptionPane.showMessageDialog(component, e.message, "Invalid listener", JOptionPane.ERROR_MESSAGE)
            }
    }

    /** Names of SOCKS5 rows (their table row is cosmetic), so "Start Selected" can pick the right starter. */
    private val socksByName = HashMap<String, Socks5ListenerConfig>()

    /** Adds a row for a restored listener WITHOUT starting it; use "Start Selected" to bind it. */
    fun addRestored(config: ListenerConfig) {
        if (config.name !in tableModel.names()) tableModel.add(config)
    }

    fun addRestoredSocks5(config: Socks5ListenerConfig) {
        if (config.name in tableModel.names()) return
        socksByName[config.name] = config
        tableModel.add(ListenerConfig(config.name, Protocol.TCP, config.bindHost, config.bindPort, "(socks5 dynamic)", config.bindPort))
    }

    private fun startSelected() {
        val row = table.selectedRow
        if (row < 0) return
        val config = tableModel.at(row)
        socksByName[config.name]?.let { onStartSocks5Listener(it); return }
        onStartListener(config)
    }

    private fun stopSelected() {
        val row = table.selectedRow
        if (row < 0) return
        val config = tableModel.at(row)
        onStopListener(config.name)
        socksByName.remove(config.name)
        tableModel.remove(row)
    }
}
