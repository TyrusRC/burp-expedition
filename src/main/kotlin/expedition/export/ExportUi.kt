package expedition.export

import expedition.registry.ConnectionRegistry
import expedition.registry.Direction
import java.awt.Component
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.io.ByteArrayOutputStream
import java.io.File
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPopupMenu

/** Swing buttons for HistoryPanel: "Export HAR...", "Import HAR...", "Copy as code ▸". */
object ExportUi {
    fun buttons(parent: Component, registry: ConnectionRegistry, selectedConnection: () -> Long?, onChanged: () -> Unit): List<JComponent> {
        val export = JButton("Export HAR...").apply {
            toolTipText = "Export the selected connection (or all, when none is selected) as HAR 1.2"
            addActionListener { exportHar(parent, this, registry, selectedConnection()) }
        }
        val import = JButton("Import HAR...").apply { addActionListener { importHar(parent, this, registry, onChanged) } }
        val copy = JButton("Copy as code ▸")
        copy.addActionListener {
            val id = selectedConnection()
            if (id == null) { JOptionPane.showMessageDialog(parent, "Select a connection first."); return@addActionListener }
            val menu = JPopupMenu()
            for (g in SnippetRegistry.all) menu.add(JMenuItem(g.label).apply { addActionListener { copySnippet(parent, registry, id, g) } })
            menu.show(copy, 0, copy.height)
        }
        return listOf(export, import, copy)
    }

    private fun exportHar(parent: Component, button: JButton, registry: ConnectionRegistry, id: Long?) {
        val chooser = JFileChooser().apply { dialogTitle = "Export HAR"; selectedFile = File("expedition.har") }
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return
        val target = chooser.selectedFile
        expedition.ui.BackgroundTask.run(parent, button, "Exporting...", "Export", {
            val r = HarCodec.export(registry, id)
            target.writeText(r.json)
            "Exported ${r.entries} HTTP exchanges (${r.skippedConnections} non-HTTP connections skipped)."
        })
    }

    private fun importHar(parent: Component, button: JButton, registry: ConnectionRegistry, onChanged: () -> Unit) {
        val chooser = JFileChooser().apply { dialogTitle = "Import HAR" }
        if (chooser.showOpenDialog(parent) != JFileChooser.APPROVE_OPTION) return
        val source = chooser.selectedFile
        expedition.ui.BackgroundTask.run(parent, button, "Importing...", "Import", {
            val r = HarCodec.import(registry, source.readText())
            "Imported ${r.connectionsAdded} connections, ${r.messagesAdded} messages (${r.skippedEntries} entries skipped)."
        }, afterSuccess = onChanged)
    }

    private fun copySnippet(parent: Component, registry: ConnectionRegistry, id: Long, g: SnippetGenerator) {
        try {
            val conn = registry.connection(id) ?: return
            val o = ByteArrayOutputStream()
            registry.messagesFor(id).filter { it.direction == Direction.CLIENT_TO_UPSTREAM && !it.isNote }.forEach { o.write(it.rawBytes) }
            val code = g.generate(SnippetRequest.fromRaw(o.toByteArray(), conn.upstreamAddress, conn.tls))
            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(code), null)
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(parent, "Cannot generate snippet: ${e.message}", "Error", JOptionPane.ERROR_MESSAGE)
        }
    }
}
