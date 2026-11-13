package expedition.ui

import expedition.dissector.DissectorRegistry
import expedition.registry.ConnectionRegistry
import expedition.session.FlowTagStore
import expedition.session.SessionSnapshot
import expedition.session.SessionStore
import java.awt.BorderLayout
import java.io.File
import javax.swing.*
import javax.swing.table.AbstractTableModel

class HistoryPanel(
    private val registry: ConnectionRegistry,
    private val dissectorRegistry: DissectorRegistry,
    private val flowTagStore: FlowTagStore = FlowTagStore()
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
        val tagButton = JButton("Tag Selected...").apply { addActionListener { tagSelected() } }
        val exportButton = JButton("Export Session...").apply { addActionListener { exportSession(this) } }
        val importButton = JButton("Import Session...").apply { addActionListener { importSession(this) } }
        val buttonPanel = JPanel().apply { add(refreshButton); add(replayButton); add(tagButton); add(exportButton); add(importButton) }
        expedition.export.ExportUi.buttons(buttonPanel,registry, { connectionTable.selectedRow.takeIf { it >= 0 }?.let { connectionModel.at(it).connectionId } }, ::refresh).forEach { buttonPanel.add(it) }
        buttonPanel.add(expedition.rules.RulesUi.createFromHistoryButton(registry) { connectionTable.selectedRow.takeIf { it >= 0 }?.let { connectionModel.at(it).connectionId } })

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

    private fun tagSelected() {
        val row = connectionTable.selectedRow
        if (row < 0) return
        val id = connectionModel.at(row).connectionId
        val tag = JOptionPane.showInputDialog(component, "Tag for connection #$id (current: ${flowTagStore.tags(id)})")
            ?.trim().orEmpty()
        if (tag.isNotEmpty()) flowTagStore.tag(id, tag)
    }

    private fun exportSession(button: AbstractButton) {
        val chooser = JFileChooser().apply { dialogTitle = "Export session to JSON" }
        if (chooser.showSaveDialog(component) != JFileChooser.APPROVE_OPTION) return
        val target = chooser.selectedFile
        BackgroundTask.run(component, button, "Exporting...", "Export", {
            val snapshot = SessionSnapshot(registry.allConnections(), registry.allMessages(), flowTagStore.all())
            target.writeText(SessionStore.export(snapshot))
            "Exported ${snapshot.connections.size} connections."
        })
    }

    private fun importSession(button: AbstractButton) {
        val chooser = JFileChooser().apply { dialogTitle = "Import session JSON" }
        if (chooser.showOpenDialog(component) != JFileChooser.APPROVE_OPTION) return
        val source = File(chooser.selectedFile.path)
        BackgroundTask.run(component, button, "Importing...", "Import", {
            val snapshot = SessionStore.import(source.readText())
            val restored = SessionStore.restore(snapshot, registry, flowTagStore)
            "Imported ${restored.connectionsAdded} connections, ${restored.messagesAdded} messages (${restored.skippedDuplicates} duplicates skipped)."
        }, afterSuccess = ::refresh)
    }

    private fun renderMessagesFor(connectionId: Long) {
        messagesArea.text = "Loading..."
        DisplayLimit.worker.execute {
            val shown = DisplayLimit.joinBounded(registry.messagesFor(connectionId).asSequence().map { message ->
                val dissector = dissectorRegistry.dissectorFor(message)
                "[${message.direction}] ${DisplayLimit.truncate(dissector.render(message), totalBytes = message.rawBytes.size).text}"
            })
            SwingUtilities.invokeLater {
                // Ignore stale results if the selection moved on.
                val row = connectionTable.selectedRow
                if (row >= 0 && connectionModel.at(row).connectionId == connectionId) {
                    messagesArea.text = shown.text
                    messagesArea.caretPosition = 0
                }
            }
        }
    }

    private fun replaySelected() {
        val row = connectionTable.selectedRow
        if (row < 0) return
        val summary = connectionModel.at(row)
        val (host, port) = UpstreamAddressParser.parse(summary.upstreamAddress)
        DisplayLimit.worker.execute {
            val firstClientMessage = registry.messagesFor(summary.connectionId)
                .firstOrNull { it.direction == expedition.registry.Direction.CLIENT_TO_UPSTREAM } ?: return@execute
            val newConnectionId = registry.openConnection("${summary.listenerName}-replay", summary.protocol, "replay", summary.upstreamAddress)
            registry.recordMessage(newConnectionId, expedition.registry.Direction.CLIENT_TO_UPSTREAM, firstClientMessage.rawBytes)
            val response = try {
                replaySender.replay(summary.protocol, host, port, firstClientMessage.rawBytes)
            } catch (e: Exception) { ByteArray(0) }
            if (response.isNotEmpty()) {
                registry.recordMessage(newConnectionId, expedition.registry.Direction.UPSTREAM_TO_CLIENT, response)
            }
            registry.closeConnection(newConnectionId)
            SwingUtilities.invokeLater { refresh() }
        }
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
