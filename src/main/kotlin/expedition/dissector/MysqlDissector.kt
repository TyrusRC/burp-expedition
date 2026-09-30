package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * MySQL client/server protocol dissector for a single packet per relay chunk. `COM_QUERY`
 * packets render their SQL and round-trip with the 3-byte length header recomputed on edit;
 * other packets render a summary and round-trip through a `raw: hex:` line.
 *
 * NOTE: one packet consuming the whole buffer. Result-set/handshake packet internals beyond
 * the command byte are not decoded (shown as raw hex).
 */
class MysqlDissector : Dissector {

    private data class Packet(val seq: Int, val payload: ByteArray, val total: Int)

    override fun supports(message: ProxyMessage): Boolean {
        val p = parse(message.rawBytes) ?: return false
        return p.total == message.rawBytes.size
    }

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        if (p.payload.isNotEmpty() && p.payload[0] == 0x03.toByte()) { // COM_QUERY
            val sql = String(p.payload, 1, p.payload.size - 1, Charsets.UTF_8)
            return "MySQL Query\nsql: $sql"
        }
        return "MySQL packet seq=${p.seq} len=${p.payload.size}\nraw: hex:${message.rawBytes.toHex()}"
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val lines = edited.split("\n").map { it.trim() }
        if (edited.startsWith("MySQL Query")) {
            // Preserve the full query after the "sql:" marker (newlines/spaces included).
            val sql = edited.substringAfter("sql:").removePrefix(" ")
            val sqlBytes = sql.toByteArray(Charsets.UTF_8)
            val payloadLen = 1 + sqlBytes.size // command byte + sql
            val out = ArrayList<Byte>()
            out.add((payloadLen and 0xff).toByte())
            out.add(((payloadLen ushr 8) and 0xff).toByte())
            out.add(((payloadLen ushr 16) and 0xff).toByte())
            out.add(0) // sequence id 0
            out.add(0x03) // COM_QUERY
            out.addAll(sqlBytes.toList())
            return out.toByteArray()
        }
        val rawLine = lines.firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private fun parse(bytes: ByteArray): Packet? {
        if (bytes.size < 5) return null
        val len = (bytes[0].toInt() and 0xff) or ((bytes[1].toInt() and 0xff) shl 8) or ((bytes[2].toInt() and 0xff) shl 16)
        val seq = bytes[3].toInt() and 0xff
        val total = 4 + len
        if (len == 0 || total > bytes.size) return null
        return Packet(seq, bytes.copyOfRange(4, total), total)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
