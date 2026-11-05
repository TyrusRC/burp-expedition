package expedition.ui

import expedition.dns.DnsController
import expedition.dns.DnsRedirector
import java.awt.BorderLayout
import java.awt.GridLayout
import javax.swing.*

/**
 * DNS redirector panel: edit spoof rules (one `host ip` per line; `#` comments and blanks
 * ignored), a catch-all default IP and a bind port, then Start/Stop the resolver.
 */
class DnsPanel(private val controller: DnsController) {
    private val rulesArea = JTextArea("# one rule per line:  host  ip\n# e.g.  *.example.com  127.0.0.1\n")
    private val defaultIpField = JTextField()
    private val portField = JTextField("53")
    private val status = JLabel("Stopped.")
    val component: JComponent

    init {
        val start = JButton("Start").apply { addActionListener { start() } }
        val stop = JButton("Stop").apply { addActionListener { controller.stop(); status.text = "Stopped." } }
        val form = JPanel(GridLayout(0, 2)).apply {
            add(JLabel("Default IP (catch-all, optional)")); add(defaultIpField)
            add(JLabel("Bind port (53 needs privileges)")); add(portField)
        }
        val south = JPanel().apply { add(start); add(stop); add(status) }
        component = JPanel(BorderLayout()).apply {
            add(form, BorderLayout.NORTH)
            add(JScrollPane(rulesArea), BorderLayout.CENTER)
            add(south, BorderLayout.SOUTH)
        }
    }

    private fun start() {
        val rules = DnsRulesParser.parse(rulesArea.text)
        val defaultIp = defaultIpField.text.ifBlank { null }
        if (rules.isEmpty() && defaultIp == null) {
            JOptionPane.showMessageDialog(component, "Add at least one rule or a default IP.", "DNS", JOptionPane.WARNING_MESSAGE)
            return
        }
        val port = portField.text.trim().toIntOrNull() ?: 53
        try {
            // Bind all interfaces so the target host can reach the resolver, not just loopback.
            val bound = controller.start("0.0.0.0", port, rules, defaultIp)
            status.text = "Running on port $bound."
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(component,
                "Failed to start DNS on port $port: ${e.message}\n(Port 53 requires root/admin.)",
                "DNS", JOptionPane.ERROR_MESSAGE)
        }
    }
}

/** Parses the rules text area ("host ip" per line) into redirect rules. Pure, so it is unit tested. */
object DnsRulesParser {
    fun parse(text: String): List<DnsRedirector.Rule> = text.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .mapNotNull { line ->
            val parts = line.split(Regex("\\s+"))
            if (parts.size >= 2 && parts[0].isNotBlank() && parts[1].isNotBlank())
                DnsRedirector.Rule(parts[0], parts[1]) else null
        }
        .toList()
}
