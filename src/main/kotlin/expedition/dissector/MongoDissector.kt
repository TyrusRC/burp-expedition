package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * MongoDB wire-protocol dissector. Decodes the 16-byte message header (length, requestID,
 * responseTo, opCode) into a readable summary; the body (BSON / OP_MSG sections) is shown
 * as raw hex and edits round-trip through the `raw: hex:` line.
 *
 * NOTE: header + raw body only — BSON decoding is out of scope for v1.
 */
class MongoDissector : Dissector {

    private val opNames = mapOf(
        1 to "OP_REPLY", 2001 to "OP_UPDATE", 2002 to "OP_INSERT", 2004 to "OP_QUERY",
        2005 to "OP_GET_MORE", 2006 to "OP_DELETE", 2007 to "OP_KILL_CURSORS",
        2010 to "OP_COMMAND", 2011 to "OP_COMMANDREPLY", 2012 to "OP_COMPRESSED", 2013 to "OP_MSG"
    )

    private data class Header(val length: Int, val requestId: Int, val responseTo: Int, val opCode: Int)

    override fun supports(message: ProxyMessage): Boolean {
        val h = parse(message.rawBytes) ?: return false
        return h.length == message.rawBytes.size
    }

    override fun render(message: ProxyMessage): String {
        val h = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val op = opNames[h.opCode] ?: "opCode=${h.opCode}"
        return "Mongo $op reqId=${h.requestId} respTo=${h.responseTo} len=${h.length}\nraw: hex:${message.rawBytes.toHex()}"
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val rawLine = edited.split("\n").map { it.trim() }
            .firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private fun parse(bytes: ByteArray): Header? {
        if (bytes.size < 16) return null
        fun le(i: Int) = (bytes[i].toInt() and 0xff) or ((bytes[i + 1].toInt() and 0xff) shl 8) or
            ((bytes[i + 2].toInt() and 0xff) shl 16) or ((bytes[i + 3].toInt() and 0xff) shl 24)
        val length = le(0)
        val opCode = le(12)
        if (length < 16 || opCode !in opNames.keys) return null
        return Header(length, le(4), le(8), opCode)
    }


}
