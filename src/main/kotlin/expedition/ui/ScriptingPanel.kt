package expedition.ui

import expedition.script.ScriptHooks
import java.awt.BorderLayout
import javax.swing.*

/**
 * Operator scripting panel: edit a JSR-223 script that transforms every forwarded message.
 * Full JVM access, no sandbox — see [ScriptHooks]. Apply compiles and installs; a compile
 * error is shown and the previous script stays active.
 */
class ScriptingPanel(private val hooks: ScriptHooks) {
    private val editor = JTextArea(hooks.source ?: "").apply { tabSize = 2 }
    private val status = JLabel()
    val component: JComponent

    init {
        val apply = JButton("Apply").apply { addActionListener { apply() } }
        val clear = JButton("Clear").apply { addActionListener { editor.text = ""; apply() } }
        val help = JLabel(
            "<html>Bindings: <b>bytes</b> (byte[]), <b>direction</b> (String), <b>connectionId</b> (long). " +
            "Return a byte[]/String to replace, or null to leave unchanged. " +
            "<i>Runs with full JVM privileges.</i></html>")
        val south = JPanel().apply { add(apply); add(clear); add(status) }
        component = JPanel(BorderLayout()).apply {
            add(help, BorderLayout.NORTH)
            add(JScrollPane(editor), BorderLayout.CENTER)
            add(south, BorderLayout.SOUTH)
        }
        refreshStatus()
    }

    private fun apply() {
        try {
            hooks.setScript(editor.text.ifBlank { null })
            status.text = if (hooks.source == null) "Cleared." else "Applied."
        } catch (e: IllegalStateException) {
            JOptionPane.showMessageDialog(component, e.message, "Scripting unavailable", JOptionPane.WARNING_MESSAGE)
        } catch (e: IllegalArgumentException) {
            JOptionPane.showMessageDialog(component, e.message, "Script error", JOptionPane.ERROR_MESSAGE)
        }
        refreshStatus()
    }

    private fun refreshStatus() {
        if (!hooks.engineAvailable) status.text = "No JSR-223 engine on the classpath — scripting disabled."
    }
}
