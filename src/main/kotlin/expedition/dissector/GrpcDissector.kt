package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * gRPC length-prefixed message framing (the "Length-Prefixed-Message" of the gRPC wire
 * protocol), as it appears on a raw relay or inside an HTTP/2 DATA frame: one or more
 * messages, each `[1-byte compression flag][4-byte big-endian length][message bytes]`.
 *
 * Uncompressed messages (flag 0) are decoded nested through [payloadDissector] (protobuf by
 * default) and edits are re-encoded with the length prefix recomputed. Compressed messages
 * (flag 1) are shown as hex and round-trip verbatim — we don't carry a gzip/deflate codec.
 *
 * Editable text format, one message per block:
 *   `#grpc <index> u`           followed by the protobuf field lines (uncompressed)
 *   `#grpc <index> c hex:<hex>` single line (compressed, opaque)
 *
 * NOTE: to keep false positives low (the 5-byte prefix alone is weak), supports() requires
 * every frame to tile the buffer exactly and at least one uncompressed frame to parse as
 * valid protobuf. A buffer of only compressed frames is left to the hex default.
 */
class GrpcDissector(
    private val payloadDissector: Dissector = ProtobufDissector(),
) : Dissector {

    private class Frame(val compressed: Boolean, val payload: ByteArray)

    private fun innerMessage(original: ProxyMessage, payload: ByteArray) =
        original.copy(rawBytes = payload)

    private fun parseFrames(bytes: ByteArray): List<Frame>? {
        if (bytes.size < 5) return null
        val frames = ArrayList<Frame>()
        var pos = 0
        while (pos < bytes.size) {
            if (pos + 5 > bytes.size) return null // truncated header
            val flag = bytes[pos].toInt() and 0xff
            if (flag != 0 && flag != 1) return null
            val len = ((bytes[pos + 1].toInt() and 0xff) shl 24) or
                ((bytes[pos + 2].toInt() and 0xff) shl 16) or
                ((bytes[pos + 3].toInt() and 0xff) shl 8) or
                (bytes[pos + 4].toInt() and 0xff)
            if (len < 0) return null
            val start = pos + 5
            val end = start.toLong() + len
            if (end > bytes.size) return null // declared length overruns the buffer
            frames.add(Frame(flag == 1, bytes.copyOfRange(start, end.toInt())))
            pos = end.toInt()
        }
        return frames.ifEmpty { null }
    }

    override fun supports(message: ProxyMessage): Boolean {
        val frames = parseFrames(message.rawBytes) ?: return false
        // Require at least one uncompressed frame that is valid, non-empty protobuf — this is
        // what distinguishes a real gRPC stream from arbitrary length-prefixed binary.
        return frames.any { !it.compressed && it.payload.isNotEmpty() &&
            payloadDissector.supports(innerMessage(message, it.payload)) }
    }

    override fun render(message: ProxyMessage): String {
        val frames = parseFrames(message.rawBytes) ?: return HexStringDissector().render(message)
        return frames.mapIndexed { i, f ->
            if (f.compressed) "#grpc $i c hex:${f.payload.toHex()}"
            else "#grpc $i u\n${payloadDissector.render(innerMessage(message, f.payload))}"
        }.joinToString("\n")
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val out = ArrayList<Byte>()
        var current: StringBuilder? = null
        var compressedHex: String? = null

        fun flush() {
            val body = current ?: return
            val payload = if (compressedHex != null) hexToBytes(compressedHex!!)
                else payloadDissector.parseEdit(body.toString().trim(), original)
            out.add(if (compressedHex != null) 0x01 else 0x00)
            out.add((payload.size ushr 24).toByte()); out.add((payload.size ushr 16).toByte())
            out.add((payload.size ushr 8).toByte()); out.add(payload.size.toByte())
            out.addAll(payload.toList())
            current = null; compressedHex = null
        }

        for (line in edited.split("\n")) {
            if (line.startsWith("#grpc ")) {
                flush()
                current = StringBuilder()
                val parts = line.removePrefix("#grpc ").trim().split(" ", limit = 3)
                // parts: [index, flag, maybe "hex:..."]
                if (parts.getOrNull(1) == "c") compressedHex = parts.getOrNull(2)?.removePrefix("hex:")?.trim()
            } else if (current != null && compressedHex == null) {
                if (current!!.isNotEmpty()) current!!.append("\n")
                current!!.append(line)
            }
        }
        flush()
        return out.toByteArray()
    }
}
