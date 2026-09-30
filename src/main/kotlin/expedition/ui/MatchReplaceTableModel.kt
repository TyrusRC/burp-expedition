package expedition.ui

import expedition.matchreplace.MatchReplaceEngine
import expedition.matchreplace.MatchReplaceRule
import javax.swing.table.AbstractTableModel

class MatchReplaceTableModel(private val engine: MatchReplaceEngine) : AbstractTableModel() {
    private val columns = listOf("Type", "Match", "Replace", "Enabled", "Decoded")
    private var rows: List<MatchReplaceRule> = engine.rules()

    override fun getRowCount() = rows.size
    override fun getColumnCount() = columns.size
    override fun getColumnName(column: Int) = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = with(rows[rowIndex]) {
        when (columnIndex) {
            0 -> matchType.name
            1 -> matchValue
            2 -> replaceValue
            3 -> enabled.toString()
            4 -> decoded.toString()
            else -> ""
        }
    }

    fun refresh() {
        rows = engine.rules()
        fireTableDataChanged()
    }

    fun at(row: Int): MatchReplaceRule = rows[row]
}
