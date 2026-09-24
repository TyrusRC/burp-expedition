package expedition.dissector

import expedition.registry.ProxyMessage

interface Dissector {
    fun supports(message: ProxyMessage): Boolean
    fun render(message: ProxyMessage): String
    fun parseEdit(edited: String, original: ProxyMessage): ByteArray
}
