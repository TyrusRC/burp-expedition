package expedition.rules

import expedition.registry.ConnectionRegistry
import expedition.server.Json
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.*
import javax.swing.table.AbstractTableModel

/** Glue for hooks in existing UI classes (HistoryPanel) that do not hold the engine themselves. */
object RulesUi {
    @Volatile var engine: RulesEngine? = null
    @Volatile var onRulesChanged: (() -> Unit)? = null
    /** Banner shown at the top of the Rules tab (set by the extension after a project restore). */
    @Volatile var restoreNotice: String? = null

    /** Banner text for [count] rules restored from the project (always disabled), or null when none. */
    fun restoreNoticeText(count: Int): String? =
        if (count > 0) "$count rule${if (count == 1) "" else "s"} restored disabled \u2014 review and enable." else null

    /** "Create rule from selected message" for the History tab. */
    fun createFromHistoryButton(registry: ConnectionRegistry, selectedConnection: () -> Long?): JButton =
        JButton("Create rule from selected message").apply {
            addActionListener {
                val eng = engine ?: return@addActionListener JOptionPane.showMessageDialog(this, "Rules engine not available")
                val conn = selectedConnection() ?: return@addActionListener JOptionPane.showMessageDialog(this, "Select a connection first")
                val messages = registry.messagesFor(conn)
                val ex = RuleFromTraffic.exchanges(messages)
                if (ex.isEmpty()) return@addActionListener JOptionPane.showMessageDialog(this, "No HTTP/1.x exchange in connection #$conn")
                val labels = ex.map { it.label }.toTypedArray()
                val default = ex.lastOrNull { it.response != null }?.label ?: labels.last()
                val pick = JOptionPane.showInputDialog(this, "Exchange to turn into a mock rule:", "Create rule",
                    JOptionPane.QUESTION_MESSAGE, null, labels, default) ?: return@addActionListener
                val rule = eng.add(RuleFromTraffic.build(ex[labels.indexOf(pick)], conn))
                onRulesChanged?.invoke()
                JOptionPane.showMessageDialog(this, "Added rule '${rule.label}' (Rules tab).")
            }
        }
}

/** "Rules" tab: ordered rule table with add / edit / delete / enable / move. */
class RulesPanel(private val engine: RulesEngine, private val registry: ConnectionRegistry) {
    private val model = RulesTableModel(engine)
    private val table = JTable(model)
    val component: JComponent

    init {
        RulesUi.engine = engine
        RulesUi.onRulesChanged = { SwingUtilities.invokeLater { refresh() } }
        table.selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION
        table.columnModel.getColumn(0).maxWidth = 40
        table.columnModel.getColumn(1).maxWidth = 40
        table.columnModel.getColumn(5).maxWidth = 80
        table.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseClicked(e: java.awt.event.MouseEvent) { if (e.clickCount == 2) edit() }
        })
        val webhooks = JCheckBox("Allow webhooks", engine.webhooksEnabled).apply {
            toolTipText = "Webhook/callback actions only send anything while this is ticked"
            addActionListener { engine.webhooksEnabled = isSelected }
        }
        val buttons = JPanel().apply {
            add(JButton("Add...").apply { addActionListener { add() } })
            add(JButton("Edit...").apply { addActionListener { edit() } })
            add(JButton("Delete").apply { addActionListener { selected()?.let { engine.remove(it.id); refresh() } } })
            add(JButton("Enable/Disable").apply { addActionListener { selected()?.let { engine.setEnabled(it.id, !it.enabled); refresh() } } })
            add(JButton("Up").apply { addActionListener { move(-1) } })
            add(JButton("Down").apply { addActionListener { move(1) } })
            add(JButton("Reset hits").apply { addActionListener { engine.resetHits(); refresh() } })
            add(JButton("Refresh").apply { addActionListener { refresh() } })
            add(webhooks)
        }
        val help = JLabel("<html>HTTP/1.x rules (plain or TLS-MITM'd TCP listeners). First match wins; rules with only " +
            "transform/delay/breakpoint actions chain into the next matching rule. Empty list = traffic untouched.</html>")
        val notice = RulesUi.restoreNotice?.let { text ->
            JLabel(text).apply {
                isOpaque = true; background = java.awt.Color(0xFFF3CD); foreground = java.awt.Color(0x664D03)
                border = BorderFactory.createEmptyBorder(4, 8, 4, 8)
            }
        }
        val top = JPanel(BorderLayout()).apply {
            if (notice != null) add(notice, BorderLayout.NORTH)
            add(help, BorderLayout.CENTER)
        }
        component = JPanel(BorderLayout()).apply {
            add(top, BorderLayout.NORTH)
            add(JScrollPane(table), BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
        }
        refresh()
    }

    fun refresh() {
        val sel = selected()?.id
        model.reload()
        sel?.let { id -> engine.rules().indexOfFirst { it.id == id }.takeIf { it >= 0 }?.let { table.setRowSelectionInterval(it, it) } }
    }

    private fun selected(): HttpRule? = table.selectedRow.takeIf { it >= 0 }?.let { model.at(it) }

    private fun move(delta: Int) {
        val r = selected() ?: return
        val i = engine.rules().indexOfFirst { it.id == r.id }
        engine.moveTo(r.id, i + delta)
        refresh()
    }

    private fun add() {
        val rule = RuleEditor.show(component, null) ?: return
        engine.add(rule); refresh()
    }

    private fun edit() {
        val r = selected() ?: return
        val rule = RuleEditor.show(component, r) ?: return
        engine.update(r.id, rule); refresh()
    }
}

internal class RulesTableModel(private val engine: RulesEngine) : AbstractTableModel() {
    private val cols = listOf("#", "On", "Name", "Match", "Actions", "Hits")
    private var rows: List<HttpRule> = emptyList()

    fun reload() { rows = engine.rules(); fireTableDataChanged() }
    fun at(i: Int) = rows[i]

    override fun getRowCount() = rows.size
    override fun getColumnCount() = cols.size
    override fun getColumnName(c: Int) = cols[c]
    override fun getColumnClass(c: Int): Class<*> = if (c == 1) java.lang.Boolean::class.java else String::class.java
    override fun isCellEditable(r: Int, c: Int) = c == 1

    override fun setValueAt(v: Any?, r: Int, c: Int) {
        if (c == 1) { engine.setEnabled(rows[r].id, v == true); reload() }
    }

    override fun getValueAt(r: Int, c: Int): Any = with(rows[r]) {
        when (c) {
            0 -> (r + 1).toString()
            1 -> enabled
            2 -> label
            3 -> summary(matcher)
            4 -> actions.joinToString(" → ") { RuleCodec.actionMap(it)["type"].toString() }
            5 -> engine.hitCount(id).toString() + (times?.let { "/$it" } ?: "")
            else -> ""
        }
    }

    private fun summary(m: RuleMatcher): String = buildList {
        if (m.direction == RuleDirection.RESPONSE) add("[response]")
        m.method?.let { add(it) }
        m.host?.let { add(it) }
        m.port?.let { add(":$it") }
        m.path?.let { add(it) }
        m.pathRegex?.let { add("~$it") }
        m.headers.forEach { add("${it.name}${it.valueRegex?.let { v -> "~$v" } ?: ""}") }
        m.bodyRegex?.let { add("body~$it") }
        m.status?.let { add("status=$it") }
        m.listener?.let { add("listener=$it") }
    }.joinToString(" ").ifEmpty { "(any)" }
}

/** Minimal form: matcher fields + actions as a JSON array (with templates). */
internal object RuleEditor {
    private val TEMPLATES = linkedMapOf(
        "mock" to """{"type":"mock","status":200,"headers":[["Content-Type","application/json"]],"body":"{}"}""",
        "transformRequest" to """{"type":"transformRequest","setHeaders":[["X-Test","1"]],"removeHeaders":[],"replace":[{"regex":"foo","with":"bar"}]}""",
        "transformResponse" to """{"type":"transformResponse","setHeaders":[["X-Test","1"]],"replace":[{"regex":"foo","with":"bar"}]}""",
        "redirect" to """{"type":"redirect","url":"http://127.0.0.1:8080","keepHost":false,"forwardCredentials":false,"insecureTls":false}""",
        "delay" to """{"type":"delay","ms":1000,"jitterMs":0}""",
        "timeout" to """{"type":"timeout"}""",
        "close" to """{"type":"close"}""",
        "reset" to """{"type":"reset"}""",
        "passthrough" to """{"type":"passthrough"}""",
        "breakpoint" to """{"type":"breakpoint","request":true,"response":false}""",
        "webhook" to """{"type":"webhook","url":"http://127.0.0.1:9000/hook","respond":false,"allowLocal":true}""",
    )

    fun show(parent: JComponent, existing: HttpRule?): HttpRule? {
        val r = existing ?: HttpRule(actions = listOf(RuleAction.MockResponse(body = BodySource.Text("mocked by Expedition"))))
        val m = r.matcher
        val name = JTextField(r.name, 30)
        val enabled = JCheckBox("Enabled", r.enabled)
        val times = JTextField(r.times?.toString() ?: "", 6)
        val direction = JComboBox(arrayOf("request", "response")).apply { selectedIndex = m.direction.ordinal }
        val method = JTextField(m.method ?: "", 12)
        val host = JTextField(m.host ?: "", 20)
        val port = JTextField(m.port?.toString() ?: "", 6)
        val path = JTextField(m.path ?: "", 20)
        val pathRegex = JTextField(m.pathRegex ?: "", 20)
        val headers = JTextArea(m.headers.joinToString("\n") { it.name + (it.valueRegex?.let { v -> ": $v" } ?: "") }, 3, 30)
        val bodyRegex = JTextField(m.bodyRegex ?: "", 20)
        val status = JTextField(m.status?.toString() ?: "", 6)
        val listener = JTextField(m.listener ?: "", 12)
        val actions = JTextArea(r.actions.joinToString(",\n", "[\n", "\n]") { Json.obj(RuleCodec.actionMap(it)) }, 10, 50)
        val template = JComboBox(TEMPLATES.keys.toTypedArray())
        val insert = JButton("Append action").apply {
            addActionListener {
                val t = TEMPLATES[template.selectedItem as String] ?: return@addActionListener
                val text = actions.text.trim()
                actions.text = if (text.endsWith("]") && text.length > 2 && text.trimEnd(']').trim() != "[")
                    text.removeSuffix("]").trimEnd() + ",\n$t\n]" else "[\n$t\n]"
            }
        }
        val form = JPanel(GridBagLayout())
        var row = 0
        fun line(label: String, c: JComponent) {
            form.add(JLabel(label), GridBagConstraints().apply { gridx = 0; gridy = row; anchor = GridBagConstraints.EAST; insets = Insets(2, 4, 2, 4) })
            form.add(c, GridBagConstraints().apply { gridx = 1; gridy = row++; fill = GridBagConstraints.HORIZONTAL; weightx = 1.0; insets = Insets(2, 4, 2, 4) })
        }
        line("Name", name); line("", enabled); line("Times (blank = ∞)", times)
        line("Match direction", direction); line("Method (GET|POST)", method); line("Host (glob)", host)
        line("Port", port); line("Path (glob, no query)", path); line("Path+query regex", pathRegex)
        line("Headers (Name: value-regex per line)", JScrollPane(headers)); line("Body regex", bodyRegex)
        line("Response status", status); line("Listener", listener)
        line("Actions (JSON array)", JScrollPane(actions))
        line("", JPanel().apply { add(template); add(insert) })
        val scroll = JScrollPane(form).apply { preferredSize = Dimension(720, 600) }
        while (true) {
            val res = JOptionPane.showConfirmDialog(parent, scroll, if (existing == null) "Add rule" else "Edit rule",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if (res != JOptionPane.OK_OPTION) return null
            try {
                val matchMap = linkedMapOf<String, Any?>(
                    "direction" to direction.selectedItem, "method" to method.text.trim(), "host" to host.text.trim(),
                    "port" to port.text.trim().ifEmpty { null }, "path" to path.text.trim(), "pathRegex" to pathRegex.text.ifEmpty { null },
                    "headers" to headers.text.lines().filter { it.isNotBlank() }.map { l ->
                        val i = l.indexOf(':')
                        if (i < 0) mapOf("name" to l.trim()) else mapOf("name" to l.substring(0, i).trim(), "value" to l.substring(i + 1).trim())
                    },
                    "bodyRegex" to bodyRegex.text.ifEmpty { null }, "status" to status.text.trim().ifEmpty { null },
                    "listener" to listener.text.trim(),
                )
                val parsedActions = Json.parse(actions.text.ifBlank { "[]" }) as? List<*>
                    ?: throw IllegalArgumentException("actions must be a JSON array")
                return RuleCodec.fromMap(mapOf(
                    "id" to r.id, "name" to name.text.trim(), "enabled" to enabled.isSelected,
                    "times" to times.text.trim().ifEmpty { null }, "match" to matchMap, "actions" to parsedActions,
                ))
            } catch (e: Exception) {
                JOptionPane.showMessageDialog(parent, "Invalid rule: ${e.message}", "Rules", JOptionPane.ERROR_MESSAGE)
            }
        }
    }
}
