package expedition.ui

import expedition.engine.ListenerConfig
import javax.swing.table.AbstractTableModel

class ListenerTableModel : AbstractTableModel() {
    private val columns = listOf("Name", "Protocol", "Bind", "Upstream", "TLS")
    private val rows = mutableListOf<ListenerConfig>()

    override fun getRowCount() = rows.size
    override fun getColumnCount() = columns.size
    override fun getColumnName(column: Int) = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = with(rows[rowIndex]) {
        when (columnIndex) {
            0 -> name
            1 -> protocol.name
            2 -> "$bindHost:$bindPort"
            3 -> "$upstreamHost:$upstreamPort"
            4 -> tlsMode.name
            else -> ""
        }
    }

    fun add(config: ListenerConfig) {
        rows.add(config)
        fireTableRowsInserted(rows.size - 1, rows.size - 1)
    }

    fun remove(row: Int) {
        rows.removeAt(row)
        fireTableRowsDeleted(row, row)
    }

    fun at(row: Int): ListenerConfig = rows[row]

    fun names(): Set<String> = rows.map { it.name }.toSet()
}
