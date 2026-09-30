package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * PostgreSQL wire-protocol dissector for a single message per relay chunk. Query (`Q`)
 * messages render their SQL and round-trip with the length prefix recomputed on edit;
 * other typed messages render a summary and round-trip through a `raw: hex:` line.
 *
 * NOTE: one typed message consuming the whole buffer (keeps detection strict). The
 * startup/SSLRequest messages (no type byte) are out of scope — STARTTLS handles SSLRequest.
 */
class PostgresDissector : Dissector {

    private val typeNames = mapOf(
        'Q' to "Query", 'P' to "Parse", 'B' to "Bind", 'E' to "Execute/Error", 'D' to "Describe/DataRow",
        'C' to "Close/CommandComplete", 'S' to "Sync/ParameterStatus", 'Z' to "ReadyForQuery",
        'T' to "RowDescription", 'R' to "Authentication", 'X' to "Terminate", 'H' to "Flush",
        '1' to "ParseComplete", '2' to "BindComplete", 'n' to "NoData", 'K' to "BackendKeyData"
    )

    private data class Msg(val type: Char, val body: ByteArray, val total: Int)

    override fun supports(message: ProxyMessage): Boolean {
        val m = parse(message.rawBytes) ?: return false
        return m.total == message.rawBytes.size
    }

    override fun render(message: ProxyMessage): String {
        val m = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        if (m.type == 'Q') {
            val sql = String(m.body, Charsets.UTF_8).trimEnd('\u0000')
            return "PG Query\nsql: $sql"
        }
        val name = typeNames[m.type] ?: "'${m.type}'"
        return "PG $name len=${m.total - 1}\nraw: hex:${message.rawBytes.toHex()}"
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val lines = edited.split("\n").map { it.trim() }
        if (lines.firstOrNull() == "PG Query") {
            val sql = lines.firstOrNull { it.startsWith("sql:") }?.substringAfter("sql:")?.trim() ?: ""
            val bodyLen = sql.toByteArray(Charsets.UTF_8).size + 1 // + NUL terminator
            val out = ArrayList<Byte>()
            out.add('Q'.code.toByte())
            out.addAll(intBytes(4 + bodyLen).toList()) // length includes the length field itself
            out.addAll(sql.toByteArray(Charsets.UTF_8).toList())
            out.add(0)
            return out.toByteArray()
        }
        val rawLine = lines.firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private fun parse(bytes: ByteArray): Msg? {
        if (bytes.size < 5) return null
        val type = bytes[0].toInt().toChar()
        if (type !in typeNames.keys) return null
        val length = ((bytes[1].toInt() and 0xff) shl 24) or ((bytes[2].toInt() and 0xff) shl 16) or
            ((bytes[3].toInt() and 0xff) shl 8) or (bytes[4].toInt() and 0xff)
        if (length < 4) return null
        val total = 1 + length // type byte is not counted in the length field
        if (total > bytes.size) return null
        return Msg(type, bytes.copyOfRange(5, total), total)
    }

    private fun intBytes(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
