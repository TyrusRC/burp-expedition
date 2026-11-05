package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * AMQP 0-9-1 dissector (RabbitMQ wire protocol).
 *
 * Two shapes are recognized:
 *  - The 8-byte protocol-header handshake: "AMQP" + 0x00 0x00 0x09 0x01 (version 0-9-1).
 *  - A frame: type(1) + channel(2 BE) + size(4 BE) + payload(size) + frame-end(1 = 0xCE).
 *
 * supports() is kept specific by requiring either the exact protocol header or a frame whose
 * declared size lands the mandatory 0xCE frame-end marker exactly at the end of the buffer with a
 * known frame type. That trailing-0xCE invariant is what stops it stealing other protocols' traffic.
 *
 * Security testing value: message broker inspection, credential/vhost enumeration on connection
 * methods, and basic.publish/deliver payload tampering.
 */
class AmqpDissector : Dissector {

    companion object {
        private val PROTOCOL_HEADER = byteArrayOf(
            0x41, 0x4D, 0x51, 0x50, // "AMQP"
            0x00, 0x00, 0x09, 0x01, // 0-9-1
        )

        private const val FRAME_END = 0xCE

        private val FRAME_TYPES = mapOf(
            1 to "METHOD",
            2 to "HEADER",
            3 to "BODY",
            8 to "HEARTBEAT",
        )

        private val CLASS_NAMES = mapOf(
            10 to "connection",
            60 to "basic",
        )

        // class-id -> (method-id -> method name)
        private val METHOD_NAMES = mapOf(
            10 to mapOf(
                10 to "Start",
                11 to "Start-Ok",
                40 to "Open",
                41 to "Open-Ok",
            ),
            60 to mapOf(
                40 to "Publish",
                60 to "Deliver",
            ),
        )
    }

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val sb = StringBuilder()

        when (p) {
            is Parsed.Header -> sb.append("AMQP protocol header (version 0-9-1)")
            is Parsed.Frame -> {
                val typeName = FRAME_TYPES[p.type] ?: "TYPE(${p.type})"
                sb.append("AMQP $typeName frame  channel=${p.channel}  size=${p.size}")
                if (p.type == 1 && p.classId != null && p.methodId != null) {
                    val className = CLASS_NAMES[p.classId] ?: "class(${p.classId})"
                    val methodName = METHOD_NAMES[p.classId]?.get(p.methodId) ?: "method(${p.methodId})"
                    sb.append("\n  $className.$methodName  (class=${p.classId}, method=${p.methodId})")
                }
            }
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

    private sealed interface Parsed {
        object Header : Parsed
        data class Frame(
            val type: Int,
            val channel: Int,
            val size: Int,
            val classId: Int?,
            val methodId: Int?,
        ) : Parsed
    }

    private fun parse(bytes: ByteArray): Parsed? {
        if (bytes.size == PROTOCOL_HEADER.size && bytes.contentEquals(PROTOCOL_HEADER)) {
            return Parsed.Header
        }
        // Minimum frame: type(1) + channel(2) + size(4) + frame-end(1) = 8 bytes.
        if (bytes.size < 8) return null
        val type = bytes[0].toInt() and 0xff
        if (type !in FRAME_TYPES) return null
        val channel = u16(bytes, 1)
        val size = i32(bytes, 3)
        if (size < 0) return null
        // Payload occupies [7, 7+size); the frame-end marker must sit exactly at the end.
        val frameEndPos = 7 + size
        if (frameEndPos != bytes.size - 1) return null
        if ((bytes[frameEndPos].toInt() and 0xff) != FRAME_END) return null

        var classId: Int? = null
        var methodId: Int? = null
        if (type == 1 && size >= 4) {
            classId = u16(bytes, 7)
            methodId = u16(bytes, 9)
        }
        return Parsed.Frame(type, channel, size, classId, methodId)
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
    private fun i32(b: ByteArray, i: Int) =
        ((b[i].toInt() and 0xff) shl 24) or ((b[i + 1].toInt() and 0xff) shl 16) or
        ((b[i + 2].toInt() and 0xff) shl 8) or (b[i + 3].toInt() and 0xff)
}
