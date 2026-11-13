package expedition.analysis

import expedition.registry.ConnectionRegistry
import java.awt.BorderLayout
import javax.swing.*
import javax.swing.table.DefaultTableModel

/** "Analysis" tab: findings table (compression / cache / OpenAPI) with OpenAPI spec loader. */
class AnalysisPanel(private val registry: ConnectionRegistry) {
    private val model = object : DefaultTableModel(arrayOf("Severity", "Category", "Conn", "Exchange", "Code", "Message"), 0) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    private val table = JTable(model).apply { autoCreateRowSorter = true }
    private val status = JLabel(" ")
    val component: JComponent

    init {
        val refresh = JButton("Analyze").apply { addActionListener { refresh() } }
        val load = JButton("Load OpenAPI...").apply { addActionListener { loadSpec() } }
        val clear = JButton("Clear spec").apply { addActionListener { AnalysisService.clearOpenApi(); refresh() } }
        val top = JPanel().apply { add(refresh); add(load); add(clear); add(status) }
        component = JPanel(BorderLayout()).apply {
            add(top, BorderLayout.NORTH)
            add(JScrollPane(table), BorderLayout.CENTER)
        }
    }

    private fun loadSpec() {
        val fc = JFileChooser()
        if (fc.showOpenDialog(component) != JFileChooser.APPROVE_OPTION) return
        try {
            val spec = AnalysisService.loadOpenApi(fc.selectedFile.readText())
            status.text = "Spec loaded: ${spec.title} (${spec.operationCount} operations)"
            refresh()
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(component, e.message, "Invalid OpenAPI spec", JOptionPane.ERROR_MESSAGE)
        }
    }

    fun refresh() {
        val findings = AnalysisService.report(registry)
        model.rowCount = 0
        for (f in findings.sortedByDescending { it.severity }) {
            model.addRow(arrayOf(f.severity.name, f.category, f.connectionId, f.exchange, f.code, f.message))
        }
        status.text = "${findings.size} findings" + (AnalysisService.spec?.let { " | spec: ${it.title}" } ?: "")
    }
}
