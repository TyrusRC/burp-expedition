package expedition.dissector

import expedition.registry.ProxyMessage

class HexStringDissector : Dissector {
    override fun supports(message: ProxyMessage) = true

    override fun render(message: ProxyMessage): String =
        message.rawBytes.joinToString(" ") { "%02x".format(it) }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val tokens = edited.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        return ByteArray(tokens.size) { i -> tokens[i].toInt(16).toByte() }
    }
}
