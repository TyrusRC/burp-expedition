package expedition.ui

import expedition.dissector.DissectorRegistry
import expedition.registry.ConnectionRegistry
import java.awt.BorderLayout
import javax.swing.*
import javax.swing.table.AbstractTableModel

class HistoryPanel(
    private val registry: ConnectionRegistry,
    private val dissectorRegistry: DissectorRegistry
) {
    private val connectionModel = ConnectionTableModel()
    private val connectionTable = JTable(connectionModel)
    private val messagesArea = JTextArea()
    private val replaySender = ReplaySender()
    val component: JComponent

    init {
        connectionTable.selectionModel.addListSelectionListener {
            val row = connectionTable.selectedRow
            if (row < 0) return@addListSelectionListener
            renderMessagesFor(connectionModel.at(row).connectionId)
        }
        val refreshButton = JButton("Refresh").apply { addActionListener { refresh() } }
        val replayButton = JButton("Replay Selected Connection").apply { addActionListener { replaySelected() } }
        val buttonPanel = JPanel().apply { add(refreshButton); add(replayButton) }

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(connectionTable), JScrollPane(messagesArea))
        component = JPanel(BorderLayout()).apply {
            add(split, BorderLayout.CENTER)
            add(buttonPanel, BorderLayout.SOUTH)
        }
        refresh()
    }

    fun refresh() {
        connectionModel.setAll(registry.allConnections())
    }

    private fun renderMessagesFor(connectionId: Long) {
        val rendered = registry.messagesFor(connectionId).joinToString("\n") { message ->
            val dissector = dissectorRegistry.dissectorFor(message)
            "[${message.direction}] ${dissector.render(message)}"
        }
        messagesArea.text = rendered
    }

    private fun replaySelected() {
        val row = connectionTable.selectedRow
        if (row < 0) return
        val summary = connectionModel.at(row)
        val (host, port) = UpstreamAddressParser.parse(summary.upstreamAddress)
        val firstClientMessage = registry.messagesFor(summary.connectionId)
            .firstOrNull { it.direction == expedition.registry.Direction.CLIENT_TO_UPSTREAM } ?: return

        val newConnectionId = registry.openConnection("${summary.listenerName}-replay", summary.protocol, "replay", summary.upstreamAddress)
        registry.recordMessage(newConnectionId, expedition.registry.Direction.CLIENT_TO_UPSTREAM, firstClientMessage.rawBytes)
        val response = replaySender.replay(summary.protocol, host, port, firstClientMessage.rawBytes)
        if (response.isNotEmpty()) {
            registry.recordMessage(newConnectionId, expedition.registry.Direction.UPSTREAM_TO_CLIENT, response)
        }
        registry.closeConnection(newConnectionId)
        refresh()
    }
}

class ConnectionTableModel : AbstractTableModel() {
    private val columns = listOf("Listener", "Protocol", "Client", "Upstream", "Open")
    private var rows: List<expedition.registry.ConnectionSummary> = emptyList()

    override fun getRowCount() = rows.size
    override fun getColumnCount() = columns.size
    override fun getColumnName(column: Int) = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = with(rows[rowIndex]) {
        when (columnIndex) {
            0 -> listenerName
            1 -> protocol.name
            2 -> clientAddress
            3 -> upstreamAddress
            4 -> (closedAt == null).toString()
            else -> ""
        }
    }

    fun setAll(newRows: List<expedition.registry.ConnectionSummary>) {
        rows = newRows
        fireTableDataChanged()
    }

    fun at(row: Int): expedition.registry.ConnectionSummary = rows[row]
}
