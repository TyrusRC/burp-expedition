package expedition.ui

import expedition.setup.SetupService
import expedition.setup.SetupTarget
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.*

/** "Setup" tab: pick a target, tweak parameters, copy the generated commands, or Apply/Undo. */
class SetupPanel(private val service: SetupService = SetupService()) {
    val component: JComponent = JPanel(BorderLayout(6, 6))
    private val combo = JComboBox(service.targets.toTypedArray())
    private val host = JTextField("127.0.0.1", 12)
    private val port = JTextField("8080", 6)
    private val proxyType = JComboBox(arrayOf("socks5", "http"))
    private val paramsPanel = JPanel(GridBagLayout())
    private val output = JTextArea().apply { isEditable = false; font = Font(Font.MONOSPACED, Font.PLAIN, 12) }
    private val apply = JButton("Apply")
    private val undo = JButton("Undo")
    private val fields = mutableMapOf<String, JComponent>()

    init {
        combo.renderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(l: JList<*>?, v: Any?, i: Int, s: Boolean, f: Boolean) =
                super.getListCellRendererComponent(l, (v as? SetupTarget)?.title ?: v, i, s, f)
        }
        val top = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(JLabel("Target:")); add(combo); add(JLabel("Host:")); add(host)
            add(JLabel("Port:")); add(port); add(JLabel("Proxy:")); add(proxyType)
        }
        val north = JPanel(BorderLayout()).apply { add(top, BorderLayout.NORTH); add(paramsPanel, BorderLayout.CENTER) }
        val copy = JButton("Copy").apply {
            addActionListener { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(output.text), null) }
        }
        val refresh = JButton("Refresh").apply { addActionListener { refresh() } }
        val buttons = JPanel(FlowLayout(FlowLayout.LEFT)).apply { add(refresh); add(copy); add(apply); add(undo) }
        component.add(north, BorderLayout.NORTH)
        component.add(JScrollPane(output), BorderLayout.CENTER)
        component.add(buttons, BorderLayout.SOUTH)
        combo.addActionListener { rebuildParams(); refresh() }
        apply.addActionListener { run(true) }
        undo.addActionListener { run(false) }
        rebuildParams(); refresh()
    }

    private fun target() = combo.selectedItem as SetupTarget

    private fun rebuildParams() {
        paramsPanel.removeAll(); fields.clear()
        val t = target()
        t.params.forEachIndexed { i, p ->
            val c = GridBagConstraints().apply { gridy = i; insets = Insets(2, 4, 2, 4); anchor = GridBagConstraints.WEST }
            paramsPanel.add(JLabel(p.label), c.apply { gridx = 0 })
            val f: JComponent = if (p.options.isNotEmpty()) JComboBox(p.options.toTypedArray()).apply { selectedItem = p.default }
            else JTextField(p.default, 28)
            fields[p.name] = f
            paramsPanel.add(f, c.apply { gridx = 1; fill = GridBagConstraints.HORIZONTAL; weightx = 1.0 })
            (f as? JComboBox<*>)?.addActionListener { refresh() }
        }
        apply.isVisible = t.executable; undo.isVisible = t.executable
        paramsPanel.revalidate(); paramsPanel.repaint()
    }

    private fun values(): Map<String, String> {
        val m = mutableMapOf("host" to host.text.trim(), "port" to port.text.trim(), "proxy_type" to proxyType.selectedItem as String)
        fields.forEach { (k, f) -> m[k] = when (f) { is JComboBox<*> -> f.selectedItem as String; is JTextField -> f.text.trim(); else -> "" } }
        return m
    }

    private fun refresh() {
        output.text = runCatching { target().guide(service.context(values(), target())) }.getOrElse { "error: ${it.message}" }
        output.caretPosition = 0
    }

    private fun run(isApply: Boolean) {
        val t = target()
        val ctx = try { service.context(values(), t) } catch (e: IllegalArgumentException) { output.text = "error: ${e.message}"; return }
        apply.isEnabled = false; undo.isEnabled = false
        output.text = (if (isApply) "Applying" else "Undoing") + " ${t.title}...\n"
        Thread {
            val r = if (isApply) t.apply(ctx) else t.undo(ctx)
            SwingUtilities.invokeLater {
                output.text = (if (r.ok) "OK\n" else "FAILED\n") + r.log + "\n\n----- guide -----\n" + t.guide(ctx)
                output.caretPosition = 0
                apply.isEnabled = true; undo.isEnabled = true
            }
        }.apply { isDaemon = true; name = "expedition-setup" }.start()
    }
}
