package expedition.ui

import expedition.registry.Direction
import javax.swing.AbstractListModel

class HeldMessageListModel : AbstractListModel<HeldMessageListModel.Entry>() {
    data class Entry(val heldMessageId: Long, val connectionId: Long, val direction: Direction, val bytes: ByteArray)

    private val entries = mutableListOf<Entry>()

    override fun getSize(): Int = entries.size
    override fun getElementAt(index: Int): Entry = entries[index]

    fun add(entry: Entry) {
        entries.add(entry)
        fireIntervalAdded(this, entries.size - 1, entries.size - 1)
    }

    fun removeById(heldMessageId: Long) {
        val idx = entries.indexOfFirst { it.heldMessageId == heldMessageId }
        if (idx >= 0) {
            entries.removeAt(idx)
            fireIntervalRemoved(this, idx, idx)
        }
    }
}
