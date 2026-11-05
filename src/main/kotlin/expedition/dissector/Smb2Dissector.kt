package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * SMB2/3 dissector (MS-SMB2).
 *
 * SMB2 is carried over TCP either directly or behind a 4-byte NetBIOS session header
 * (0x00 followed by a 3-byte big-endian length). Both framings are handled.
 *
 * SMB2 header (fixed 64 bytes, all multi-byte fields little-endian):
 *   ProtocolId(4) = 0xFE 'S' 'M' 'B', StructureSize(2)=64, CreditCharge(2),
 *   Status/ChannelSequence(4), Command(2), CreditRequest(2), Flags(4),
 *   NextCommand(4), MessageId(8), ...
 *
 * supports() invariant: the magic 0xFE534D42 is present (optionally after the NetBIOS
 * header) AND StructureSize == 64.
 */
class Smb2Dissector : Dissector {

    companion object {
        // 0xFE 'S' 'M' 'B'
        private val MAGIC = byteArrayOf(0xFE.toByte(), 0x53, 0x4D, 0x42)

        private const val SMB2_HEADER_SIZE = 64

        private const val FLAG_SERVER_TO_REDIR = 0x00000001 // response

        private val COMMANDS = mapOf(
            0 to "NEGOTIATE",
            1 to "SESSION_SETUP",
            2 to "LOGOFF",
            3 to "TREE_CONNECT",
            4 to "TREE_DISCONNECT",
            5 to "CREATE",
            6 to "CLOSE",
            8 to "READ",
            9 to "WRITE",
            14 to "QUERY_DIRECTORY",
            16 to "QUERY_INFO",
        )
    }

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val cmd = COMMANDS[p.command] ?: "Command(${p.command})"
        val kind = if (p.flags and FLAG_SERVER_TO_REDIR != 0) "response" else "request"
        val sb = StringBuilder()
        sb.append("SMB2 $cmd  ($kind)  messageId=${java.lang.Long.toUnsignedString(p.messageId)}")
        if (p.netbiosLen != null) sb.append("\nNetBIOS len=${p.netbiosLen}")
        sb.append("\nraw: hex:${message.rawBytes.toHex()}")
        return sb.toString()
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val rawLine = edited.split("\n").map { it.trim() }
            .firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private data class Parsed(
        val command: Int,
        val flags: Int,
        val messageId: Long,
        val netbiosLen: Int?,
    )

    private fun parse(bytes: ByteArray): Parsed? {
        // Determine the SMB2 header offset: either at the start, or after a 4-byte
        // NetBIOS session header (0x00 + 3-byte BE length) whose payload begins with the magic.
        val offset: Int
        val netbiosLen: Int?
        if (bytes.size >= 8 && bytes[0].toInt() == 0 && matchesMagic(bytes, 4)) {
            offset = 4
            netbiosLen = ((bytes[1].toInt() and 0xff) shl 16) or
                ((bytes[2].toInt() and 0xff) shl 8) or (bytes[3].toInt() and 0xff)
        } else if (matchesMagic(bytes, 0)) {
            offset = 0
            netbiosLen = null
        } else {
            return null
        }

        if (bytes.size < offset + SMB2_HEADER_SIZE) return null
        if (u16(bytes, offset + 4) != SMB2_HEADER_SIZE) return null // StructureSize must be 64

        val command = u16(bytes, offset + 12)
        val flags = i32(bytes, offset + 16)
        val messageId = u64(bytes, offset + 24)
        return Parsed(command, flags, messageId, netbiosLen)
    }

    private fun matchesMagic(b: ByteArray, at: Int): Boolean {
        if (at + MAGIC.size > b.size) return false
        for (i in MAGIC.indices) if (b[at + i] != MAGIC[i]) return false
        return true
    }

    // little-endian readers
    private fun u16(b: ByteArray, i: Int) = (b[i].toInt() and 0xff) or ((b[i + 1].toInt() and 0xff) shl 8)
    private fun i32(b: ByteArray, i: Int) =
        (b[i].toInt() and 0xff) or ((b[i + 1].toInt() and 0xff) shl 8) or
        ((b[i + 2].toInt() and 0xff) shl 16) or ((b[i + 3].toInt() and 0xff) shl 24)
    private fun u64(b: ByteArray, i: Int): Long {
        var v = 0L
        for (k in 0 until 8) v = v or ((b[i + k].toLong() and 0xff) shl (k * 8))
        return v
    }
}
