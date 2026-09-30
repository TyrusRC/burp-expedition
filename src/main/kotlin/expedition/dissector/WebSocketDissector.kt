package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * WebSocket frame dissector (RFC 6455), one frame per relay chunk. Text frames render
 * their (unmasked) payload and round-trip with masking re-applied and the length field
 * recomputed on edit; control/binary frames render a summary and round-trip through a
 * `raw: hex:` line.
 *
 * NOTE: one frame consuming the whole buffer; fragmented frames across chunks are shown as
 * raw hex. Text payloads containing a leading space or newline may not round-trip exactly.
 */
class WebSocketDissector : Dissector {

    private val opNames = mapOf(
        0 to "continuation", 1 to "text", 2 to "binary", 8 to "close", 9 to "ping", 10 to "pong"
    )

    private class Frame(
        val byte0: Int, val opcode: Int, val masked: Boolean,
        val maskKey: ByteArray?, val payload: ByteArray, val total: Int
    )

    override fun supports(message: ProxyMessage): Boolean {
        val f = parse(message.rawBytes) ?: return false
        return f.total == message.rawBytes.size
    }

    override fun render(message: ProxyMessage): String {
        val f = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        if (f.opcode == 1) return "WS text: ${String(f.payload, Charsets.UTF_8)}"
        val name = opNames[f.opcode] ?: "op${f.opcode}"
        return "WS $name len=${f.payload.size}\nraw: hex:${message.rawBytes.toHex()}"
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        if (edited.startsWith("WS text:")) {
            val f = parse(original.rawBytes) ?: return original.rawBytes
            val payload = edited.substringAfter("WS text:").removePrefix(" ").toByteArray(Charsets.UTF_8)
            val out = ArrayList<Byte>()
            out.add(f.byte0.toByte())
            val maskBit = if (f.masked) 0x80 else 0
            when {
                payload.size < 126 -> out.add((maskBit or payload.size).toByte())
                payload.size < 65536 -> {
                    out.add((maskBit or 126).toByte())
                    out.add((payload.size ushr 8).toByte()); out.add(payload.size.toByte())
                }
                else -> {
                    out.add((maskBit or 127).toByte())
                    for (s in 56 downTo 0 step 8) out.add((payload.size.toLong() ushr s).toByte())
                }
            }
            if (f.masked && f.maskKey != null) {
                out.addAll(f.maskKey.toList())
                payload.forEachIndexed { i, b -> out.add((b.toInt() xor f.maskKey[i % 4].toInt()).toByte()) }
            } else {
                out.addAll(payload.toList())
            }
            return out.toByteArray()
        }
        val rawLine = edited.split("\n").map { it.trim() }
            .firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private fun parse(bytes: ByteArray): Frame? {
        if (bytes.size < 2) return null
        val b0 = bytes[0].toInt() and 0xff
        val opcode = b0 and 0x0f
        if (opcode !in opNames.keys) return null
        val b1 = bytes[1].toInt() and 0xff
        val masked = b1 and 0x80 != 0
        val len7 = b1 and 0x7f
        var pos = 2
        val len: Int = when {
            len7 < 126 -> len7
            len7 == 126 -> {
                if (pos + 2 > bytes.size) return null
                val l = ((bytes[pos].toInt() and 0xff) shl 8) or (bytes[pos + 1].toInt() and 0xff); pos += 2; l
            }
            else -> {
                if (pos + 8 > bytes.size) return null
                var l = 0L; for (i in 0 until 8) l = (l shl 8) or (bytes[pos + i].toLong() and 0xff); pos += 8
                if (l > Int.MAX_VALUE) return null
                l.toInt()
            }
        }
        var key: ByteArray? = null
        if (masked) {
            if (pos + 4 > bytes.size) return null
            key = bytes.copyOfRange(pos, pos + 4); pos += 4
        }
        // Long guard: pos + len can overflow Int for a length near Int.MAX.
        if (len < 0 || pos.toLong() + len > bytes.size) return null
        val end = pos + len
        val raw = bytes.copyOfRange(pos, end)
        val payload = if (masked && key != null) ByteArray(raw.size) { (raw[it].toInt() xor key[it % 4].toInt()).toByte() } else raw
        return Frame(b0, opcode, masked, key, payload, end)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
