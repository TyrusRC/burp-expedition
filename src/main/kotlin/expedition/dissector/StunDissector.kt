package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * STUN/TURN message dissector (RFC 5389 / RFC 8656).
 *
 * STUN header: type(2) + length(2) + magic cookie 0x2112A442(4) + transaction ID(12) = 20 bytes.
 * Attributes follow: type(2) + length(2) + value (padded to 4-byte boundary).
 *
 * Covers: Binding Request/Response/Indication, Allocate, CreatePermission, ChannelBind,
 * Refresh, Send, Data (TURN). Parses MAPPED-ADDRESS, XOR-MAPPED-ADDRESS, ERROR-CODE,
 * SOFTWARE, REALM, NONCE, USERNAME, and REQUESTED-TRANSPORT attributes.
 *
 * Security testing value: open TURN relay detection, ICE candidate IP extraction,
 * credential enumeration, and STUN amplification checks.
 */
class StunDissector : Dissector {

    companion object {
        private const val MAGIC_COOKIE = 0x2112A442.toInt()

        private val METHOD_NAMES = mapOf(
            0x0001 to "Binding",
            0x0003 to "Allocate",
            0x0004 to "Refresh",
            0x0006 to "Send",
            0x0007 to "Data",
            0x0008 to "CreatePermission",
            0x0009 to "ChannelBind",
        )

        private val ATTR_NAMES = mapOf(
            0x0001 to "MAPPED-ADDRESS",
            0x0006 to "USERNAME",
            0x0008 to "MESSAGE-INTEGRITY",
            0x0009 to "ERROR-CODE",
            0x000A to "UNKNOWN-ATTRIBUTES",
            0x0014 to "REALM",
            0x0015 to "NONCE",
            0x0019 to "REQUESTED-TRANSPORT",
            0x0020 to "XOR-MAPPED-ADDRESS",
            0x0024 to "PRIORITY",
            0x0025 to "USE-CANDIDATE",
            0x8022 to "SOFTWARE",
            0x8028 to "FINGERPRINT",
            0x802B to "RESPONSE-ORIGIN",
            0x802C to "OTHER-ADDRESS",
        )
    }

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val sb = StringBuilder()

        val cls = when ((p.type shr 4) and 0x11) {
            0x00 -> "Request"
            0x01 -> "Indication"
            0x10 -> "Success"
            0x11 -> "Error"
            else -> "?"
        }
        val method = p.type and 0x3EEF
        val methodName = METHOD_NAMES[method] ?: "Method(0x%04x)".format(method)
        sb.append("STUN $methodName $cls  len=${p.length}  txn=${p.txnId}")

        for (attr in p.attrs) {
            val name = ATTR_NAMES[attr.type] ?: "ATTR(0x%04x)".format(attr.type)
            val value = when (attr.type) {
                0x0020 -> decodeXorMappedAddress(attr.value, p.txnIdBytes)
                0x0001 -> decodeMappedAddress(attr.value)
                0x0009 -> decodeErrorCode(attr.value)
                0x0006, 0x0014, 0x0015, 0x8022 -> String(attr.value, Charsets.UTF_8)
                0x0019 -> "protocol=${attr.value.getOrNull(0)?.toInt()?.and(0xff) ?: '?'} (17=UDP, 6=TCP)"
                else -> if (attr.value.size <= 16) attr.value.toHex() else "${attr.value.size}B"
            }
            sb.append("\n  $name: $value")
        }
        sb.append("\nraw: hex:${message.rawBytes.toHex()}")
        return sb.toString()
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val rawLine = edited.split("\n").map { it.trim() }
            .firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private data class Attr(val type: Int, val value: ByteArray)
    private data class Parsed(val type: Int, val length: Int, val txnId: String,
                              val txnIdBytes: ByteArray, val attrs: List<Attr>)

    private fun parse(bytes: ByteArray): Parsed? {
        if (bytes.size < 20) return null
        val b0 = bytes[0].toInt() and 0xff
        if (b0 and 0xC0 != 0) return null // first 2 bits must be 0
        val type = u16(bytes, 0)
        val length = u16(bytes, 2)
        val cookie = i32(bytes, 4)
        if (cookie != MAGIC_COOKIE) return null
        if (length and 3 != 0) return null // must be 4-byte aligned
        if (20 + length > bytes.size) return null

        val txnIdBytes = bytes.copyOfRange(8, 20)
        val txnId = txnIdBytes.toHex()

        val attrs = mutableListOf<Attr>()
        var pos = 20
        val end = 20 + length
        while (pos + 4 <= end) {
            val aType = u16(bytes, pos)
            val aLen = u16(bytes, pos + 2)
            pos += 4
            if (pos + aLen > end) break
            attrs.add(Attr(aType, bytes.copyOfRange(pos, pos + aLen)))
            pos += aLen
            // pad to 4-byte boundary
            val pad = (4 - (aLen and 3)) and 3
            pos += pad
        }
        return Parsed(type, length, txnId, txnIdBytes, attrs)
    }

    private fun decodeXorMappedAddress(value: ByteArray, txnId: ByteArray): String {
        if (value.size < 8) return value.toHex()
        val family = value[1].toInt() and 0xff
        val port = (u16(value, 2)) xor (MAGIC_COOKIE ushr 16)
        return if (family == 0x01 && value.size >= 8) {
            val ip = ByteArray(4) { i -> (value[4 + i].toInt() xor ((MAGIC_COOKIE ushr (24 - i * 8)) and 0xff)).toByte() }
            "${ip.joinToString(".") { (it.toInt() and 0xff).toString() }}:$port"
        } else if (family == 0x02 && value.size >= 20) {
            val xorKey = ByteArray(16)
            xorKey[0] = (MAGIC_COOKIE ushr 24).toByte()
            xorKey[1] = (MAGIC_COOKIE ushr 16).toByte()
            xorKey[2] = (MAGIC_COOKIE ushr 8).toByte()
            xorKey[3] = MAGIC_COOKIE.toByte()
            System.arraycopy(txnId, 0, xorKey, 4, 12)
            val ip6 = ByteArray(16) { i -> (value[4 + i].toInt() xor xorKey[i].toInt()).toByte() }
            "[${ip6.toHex()}]:$port"
        } else value.toHex()
    }

    private fun decodeMappedAddress(value: ByteArray): String {
        if (value.size < 8) return value.toHex()
        val family = value[1].toInt() and 0xff
        val port = u16(value, 2)
        return if (family == 0x01) {
            "${value.copyOfRange(4, 8).joinToString(".") { (it.toInt() and 0xff).toString() }}:$port"
        } else value.toHex()
    }

    private fun decodeErrorCode(value: ByteArray): String {
        if (value.size < 4) return value.toHex()
        val cls = value[2].toInt() and 0x07
        val number = value[3].toInt() and 0xff
        val code = cls * 100 + number
        val reason = if (value.size > 4) String(value, 4, value.size - 4, Charsets.UTF_8) else ""
        return "$code $reason"
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
    private fun i32(b: ByteArray, i: Int) =
        ((b[i].toInt() and 0xff) shl 24) or ((b[i+1].toInt() and 0xff) shl 16) or
        ((b[i+2].toInt() and 0xff) shl 8) or (b[i+3].toInt() and 0xff)
}
