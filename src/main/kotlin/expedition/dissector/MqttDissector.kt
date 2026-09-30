package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * MQTT 3.1.1 control-packet dissector for a single packet per message (the common
 * shape on a relay). PUBLISH packets render their topic and payload and round-trip
 * faithfully; other packet types render a summary and round-trip through a `raw hex:`
 * line, so every edit is reversible.
 *
 * NOTE: scoped to one packet that consumes the whole buffer (keeps detection strict
 * and the edit round-trip unambiguous). MQTT 5 properties are not decoded.
 */
class MqttDissector : Dissector {

    private val typeNames = arrayOf(
        "RESERVED", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL",
        "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ",
        "PINGRESP", "DISCONNECT", "AUTH"
    )

    private data class Packet(val type: Int, val flags: Int, val payload: ByteArray, val totalLen: Int)

    override fun supports(message: ProxyMessage): Boolean {
        val p = parseOne(message.rawBytes) ?: return false
        return p.type in 1..15 && p.totalLen == message.rawBytes.size
    }

    override fun render(message: ProxyMessage): String {
        val p = parseOne(message.rawBytes) ?: return HexStringDissector().render(message)
        val name = typeNames.getOrElse(p.type) { "UNKNOWN" }
        if (p.type == 3) { // PUBLISH
            val dup = (p.flags shr 3) and 1
            val qos = (p.flags shr 1) and 3
            val retain = p.flags and 1
            var pos = 0
            val topicLen = ((p.payload[0].toInt() and 0xff) shl 8) or (p.payload[1].toInt() and 0xff)
            pos = 2
            val topic = String(p.payload, pos, topicLen, Charsets.UTF_8)
            pos += topicLen
            if (qos > 0) pos += 2 // packet identifier
            val body = p.payload.copyOfRange(pos, p.payload.size)
            val bodyText = if (body.all { it in 0x20..0x7e || it == 0x09.toByte() })
                "str:${String(body, Charsets.ISO_8859_1)}" else "hex:${body.toHex()}"
            return "MQTT PUBLISH dup=$dup qos=$qos retain=$retain\ntopic: $topic\npayload: $bodyText"
        }
        return "MQTT $name flags=0x%x\nraw: hex:%s".format(p.flags, message.rawBytes.toHex())
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val lines = edited.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.firstOrNull()?.startsWith("MQTT PUBLISH") == true) return encodePublish(lines)
        val rawLine = lines.firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private fun encodePublish(lines: List<String>): ByteArray {
        val header = lines[0]
        val qos = Regex("qos=(\\d)").find(header)?.groupValues?.get(1)?.toInt() ?: 0
        val dup = Regex("dup=(\\d)").find(header)?.groupValues?.get(1)?.toInt() ?: 0
        val retain = Regex("retain=(\\d)").find(header)?.groupValues?.get(1)?.toInt() ?: 0
        val topic = lines.first { it.startsWith("topic:") }.substringAfter("topic:").trim()
        val payloadSpec = lines.first { it.startsWith("payload:") }.substringAfter("payload:").trim()
        val payload = when {
            payloadSpec.startsWith("str:") -> payloadSpec.removePrefix("str:").toByteArray(Charsets.ISO_8859_1)
            payloadSpec.startsWith("hex:") -> hexToBytes(payloadSpec.removePrefix("hex:"))
            else -> ByteArray(0)
        }
        val topicBytes = topic.toByteArray(Charsets.UTF_8)
        val variable = ArrayList<Byte>()
        variable.add((topicBytes.size shr 8).toByte())
        variable.add((topicBytes.size and 0xff).toByte())
        variable.addAll(topicBytes.toList())
        // NOTE: QoS>0 packet identifiers are not preserved (round-trip supports QoS 0);
        // editing QoS>0 PUBLISH is out of scope for v1.
        variable.addAll(payload.toList())

        val byte1 = (3 shl 4) or (dup shl 3) or (qos shl 1) or retain
        val out = ArrayList<Byte>()
        out.add(byte1.toByte())
        writeRemainingLength(variable.size, out)
        out.addAll(variable)
        return out.toByteArray()
    }

    /** Parses the first MQTT packet; null if the fixed header / remaining length is invalid. */
    private fun parseOne(bytes: ByteArray): Packet? {
        if (bytes.size < 2) return null
        val byte1 = bytes[0].toInt() and 0xff
        val type = byte1 shr 4
        val flags = byte1 and 0x0f
        var multiplier = 1
        var remaining = 0
        var pos = 1
        while (true) {
            if (pos >= bytes.size) return null
            val b = bytes[pos].toInt() and 0xff
            remaining += (b and 0x7f) * multiplier
            pos++
            if (b and 0x80 == 0) break
            multiplier *= 128
            if (multiplier > 128 * 128 * 128) return null
        }
        val end = pos + remaining
        if (end > bytes.size) return null
        return Packet(type, flags, bytes.copyOfRange(pos, end), end)
    }

    private fun writeRemainingLength(length: Int, out: ArrayList<Byte>) {
        var x = length
        do {
            var b = x % 128
            x /= 128
            if (x > 0) b = b or 0x80
            out.add(b.toByte())
        } while (x > 0)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
