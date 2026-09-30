package expedition.ui

import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchType
import java.awt.BorderLayout
import java.awt.GridLayout
import java.util.concurrent.atomic.AtomicLong
import javax.swing.*

class MatchReplacePanel(private val engine: MatchReplaceEngine) {
    private val tableModel = MatchReplaceTableModel(engine)
    private val table = JTable(tableModel)
    private val nextId = AtomicLong(1)
    val component: JComponent

    init {
        val addButton = JButton("Add Rule").apply { addActionListener { showAddDialog() } }
        val removeButton = JButton("Remove Selected").apply { addActionListener { removeSelected() } }
        val buttonPanel = JPanel().apply { add(addButton); add(removeButton) }
        component = JPanel(BorderLayout()).apply {
            add(JScrollPane(table), BorderLayout.CENTER)
            add(buttonPanel, BorderLayout.SOUTH)
        }
    }

    private fun showAddDialog() {
        val typeBox = JComboBox(MatchType.values())
        val matchField = JTextField()
        val replaceField = JTextField()
        val decodedBox = JCheckBox("Match on decoded (dissected) view and re-encode")
        val form = JPanel(GridLayout(0, 2)).apply {
            add(JLabel("Type")); add(typeBox)
            add(JLabel("Match")); add(matchField)
            add(JLabel("Replace")); add(replaceField)
            add(JLabel("Decoded")); add(decodedBox)
        }
        val result = JOptionPane.showConfirmDialog(component, form, "Add Rule", JOptionPane.OK_CANCEL_OPTION)
        if (result != JOptionPane.OK_OPTION) return

        val validated = MatchReplaceFormValidation.validate(
            typeBox.selectedItem as MatchType, matchField.text, replaceField.text, nextId.getAndIncrement(),
            decodedBox.isSelected
        )
        validated.onSuccess { rule ->
            engine.addRule(rule)
            tableModel.refresh()
        }.onFailure { error ->
            JOptionPane.showMessageDialog(component, error.message, "Invalid rule", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun removeSelected() {
        val row = table.selectedRow
        if (row < 0) return
        engine.removeRule(tableModel.at(row).id)
        tableModel.refresh()
    }
}
