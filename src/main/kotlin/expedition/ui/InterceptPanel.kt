package expedition.ui

import expedition.dissector.DissectorRegistry
import expedition.intercept.InterceptController
import expedition.registry.Direction
import expedition.registry.ProxyMessage
import java.awt.BorderLayout
import java.time.Instant
import javax.swing.*

class InterceptPanel(
    private val interceptController: InterceptController,
    private val dissectorRegistry: DissectorRegistry
) {
    private val listModel = HeldMessageListModel()
    private val list = JList(listModel)
    private val editor = JTextArea()
    val component: JComponent

    init {
        val interceptToggle = JCheckBox("Intercept is on").apply {
            addActionListener { interceptController.setEnabled(isSelected) }
        }
        list.addListSelectionListener {
            val selected = list.selectedValue ?: return@addListSelectionListener
            editor.text = renderedTextFor(selected)
        }
        val forwardButton = JButton("Forward").apply { addActionListener { forwardSelected() } }
        val dropButton = JButton("Drop").apply { addActionListener { dropSelected() } }
        val buttonPanel = JPanel().apply { add(interceptToggle); add(forwardButton); add(dropButton) }

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(list), JScrollPane(editor))
        component = JPanel(BorderLayout()).apply {
            add(split, BorderLayout.CENTER)
            add(buttonPanel, BorderLayout.SOUTH)
        }
    }

    fun onHeldMessage(heldMessageId: Long, connectionId: Long, direction: Direction, bytes: ByteArray) {
        SwingUtilities.invokeLater {
            listModel.add(HeldMessageListModel.Entry(heldMessageId, connectionId, direction, bytes))
        }
    }

    private fun renderedTextFor(entry: HeldMessageListModel.Entry): String {
        val message = ProxyMessage(entry.heldMessageId, entry.connectionId, entry.direction, Instant.now(), entry.bytes)
        return dissectorRegistry.dissectorFor(message).render(message)
    }

    private fun forwardSelected() {
        val entry = list.selectedValue ?: return
        val message = ProxyMessage(entry.heldMessageId, entry.connectionId, entry.direction, Instant.now(), entry.bytes)
        val editedBytes = dissectorRegistry.dissectorFor(message).parseEdit(editor.text, message)
        interceptController.forward(entry.heldMessageId, editedBytes)
        listModel.removeById(entry.heldMessageId)
    }

    private fun dropSelected() {
        val entry = list.selectedValue ?: return
        interceptController.drop(entry.heldMessageId)
        listModel.removeById(entry.heldMessageId)
    }
}
