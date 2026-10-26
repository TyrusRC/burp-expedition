package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * HTTP/2 binary-frame dissector for gRPC and other HTTP/2 traffic relayed
 * through Expedition's TCP proxy.
 *
 * Parses the 9-byte frame header (RFC 9113 §4.1) and renders each frame as a
 * human-readable line. DATA frame payloads that contain a gRPC length-prefixed
 * message (1-byte compressed flag + 4-byte big-endian length + protobuf) are
 * decoded by [ProtobufDissector] when the protobuf heuristic matches.
 *
 * HPACK header decompression is NOT implemented — HEADERS/CONTINUATION frames
 * show their raw payload as hex. This is intentional: HPACK requires stateful
 * compression context across frames, which a per-message dissector cannot
 * maintain. For gRPC testing the headers are usually fixed; the DATA payload
 * (protobuf) is the part the operator edits.
 *
 * Editable text format (round-trippable for DATA frames):
 * ```
 * [DATA stream=1 flags=01 END_STREAM]
 * grpc:0 1 varint 42
 * grpc:0 2 len str:hello
 * [HEADERS stream=1 flags=04 END_HEADERS]
 * hex:raw-hpack-bytes
 * ```
 *
 * On parseEdit, DATA frames with `grpc:` lines re-encode through Protobuf +
 * gRPC framing. Other frame types keep their raw hex payload.
 */
class Http2FrameDissector : Dissector {

    companion object {
        // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" — 24 bytes
        private val PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.ISO_8859_1)

        private val FRAME_TYPES = mapOf(
            0 to "DATA", 1 to "HEADERS", 2 to "PRIORITY", 3 to "RST_STREAM",
            4 to "SETTINGS", 5 to "PUSH_PROMISE", 6 to "PING", 7 to "GOAWAY",
            8 to "WINDOW_UPDATE", 9 to "CONTINUATION",
        )

        private val DATA_FLAGS = mapOf(0x01 to "END_STREAM", 0x08 to "PADDED")
        private val HEADERS_FLAGS = mapOf(
            0x01 to "END_STREAM", 0x04 to "END_HEADERS",
            0x08 to "PADDED", 0x20 to "PRIORITY",
        )
    }

    private val protobuf = ProtobufDissector()

    override fun supports(message: ProxyMessage): Boolean {
        val b = message.rawBytes
        // Connection preface or a valid-looking frame header
        if (b.size >= PREFACE.size && b.copyOfRange(0, PREFACE.size).contentEquals(PREFACE)) return true
        if (b.size < 9) return false
        val frameType = b[3].toInt() and 0xff
        if (frameType > 9) return false
        val length = ((b[0].toInt() and 0xff) shl 16) or
                     ((b[1].toInt() and 0xff) shl 8) or
                      (b[2].toInt() and 0xff)
        if (length < 0 || length > 16_777_215) return false
        // Exact fit: the first frame must fit within the message.
        // If multiple frames, a second frame header should start at 9+length.
        if (9 + length > b.size) return false
        val nextOffset = 9 + length
        if (nextOffset < b.size) {
            // Verify a plausible second frame header follows.
            if (nextOffset + 9 > b.size) return false
            val nextType = b[nextOffset + 3].toInt() and 0xff
            if (nextType > 9) return false
        }
        return true
    }

    override fun render(message: ProxyMessage): String {
        val b = message.rawBytes
        val sb = StringBuilder()
        var pos = 0

        // Skip connection preface if present
        if (b.size >= PREFACE.size && b.copyOfRange(0, PREFACE.size).contentEquals(PREFACE)) {
            sb.appendLine("[HTTP/2 CONNECTION PREFACE]")
            pos = PREFACE.size
        }

        while (pos + 9 <= b.size) {
            val length = ((b[pos].toInt() and 0xff) shl 16) or
                         ((b[pos + 1].toInt() and 0xff) shl 8) or
                          (b[pos + 2].toInt() and 0xff)
            val frameType = b[pos + 3].toInt() and 0xff
            val flags = b[pos + 4].toInt() and 0xff
            val streamId = ((b[pos + 5].toInt() and 0x7f) shl 24) or
                           ((b[pos + 6].toInt() and 0xff) shl 16) or
                           ((b[pos + 7].toInt() and 0xff) shl 8) or
                            (b[pos + 8].toInt() and 0xff)
            val typeName = FRAME_TYPES[frameType] ?: "UNKNOWN($frameType)"
            val flagStr = renderFlags(frameType, flags)
            sb.appendLine("[$typeName stream=$streamId flags=%02x$flagStr]".format(flags))

            pos += 9
            val end = (pos + length).coerceAtMost(b.size)
            val payload = if (end > pos) b.copyOfRange(pos, end) else byteArrayOf()

            if (payload.isNotEmpty()) {
                when (frameType) {
                    0 -> renderDataPayload(payload, sb) // DATA
                    4 -> renderSettings(payload, sb)     // SETTINGS
                    7 -> renderGoaway(payload, sb)       // GOAWAY
                    8 -> renderWindowUpdate(payload, sb) // WINDOW_UPDATE
                    else -> sb.appendLine("hex:${payload.toHex()}")
                }
            }
            pos = end
        }

        // Trailing bytes that don't form a complete frame
        if (pos < b.size) {
            sb.appendLine("[TRAILING ${b.size - pos}B]")
            sb.appendLine("hex:${b.copyOfRange(pos, b.size).toHex()}")
        }

        return sb.toString().trimEnd()
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val out = ArrayList<Byte>()
        val lines = edited.split("\n")
        var i = 0

        // Re-emit preface if the original had one
        if (original.rawBytes.size >= PREFACE.size &&
            original.rawBytes.copyOfRange(0, PREFACE.size).contentEquals(PREFACE)) {
            if (i < lines.size && lines[i].trim() == "[HTTP/2 CONNECTION PREFACE]") {
                out.addAll(PREFACE.toList())
                i++
            }
        }

        while (i < lines.size) {
            val line = lines[i].trim()
            i++
            if (line.isEmpty()) continue
            if (!line.startsWith("[") || !line.endsWith("]")) continue

            // Parse frame header line: [TYPE stream=N flags=XX ...]
            val parsed = parseFrameHeader(line) ?: continue
            val payloadLines = ArrayList<String>()
            while (i < lines.size) {
                val pLine = lines[i].trim()
                if (pLine.startsWith("[") && pLine.endsWith("]")) break
                payloadLines.add(pLine)
                i++
            }

            val payload = encodePayload(parsed.type, payloadLines)
            // Write 9-byte frame header
            out.add(((payload.size shr 16) and 0xff).toByte())
            out.add(((payload.size shr 8) and 0xff).toByte())
            out.add((payload.size and 0xff).toByte())
            out.add(parsed.type.toByte())
            out.add(parsed.flags.toByte())
            out.add(((parsed.streamId shr 24) and 0x7f).toByte())
            out.add(((parsed.streamId shr 16) and 0xff).toByte())
            out.add(((parsed.streamId shr 8) and 0xff).toByte())
            out.add((parsed.streamId and 0xff).toByte())
            out.addAll(payload.toList())
        }
        return out.toByteArray()
    }

    // ── Render helpers ──────────────────────────────────────────────────

    private fun renderFlags(frameType: Int, flags: Int): String {
        val map = when (frameType) {
            0 -> DATA_FLAGS
            1, 5, 9 -> HEADERS_FLAGS
            else -> emptyMap()
        }
        val names = map.entries.filter { flags and it.key != 0 }.map { it.value }
        return if (names.isEmpty()) "" else " " + names.joinToString(" ")
    }

    private fun renderDataPayload(payload: ByteArray, sb: StringBuilder) {
        // Try gRPC framing: 1 byte compressed + 4 byte BE length + protobuf
        if (payload.size >= 5) {
            val compressed = payload[0].toInt() and 0xff
            val msgLen = ((payload[1].toInt() and 0xff) shl 24) or
                         ((payload[2].toInt() and 0xff) shl 16) or
                         ((payload[3].toInt() and 0xff) shl 8) or
                          (payload[4].toInt() and 0xff)
            if (compressed <= 1 && msgLen >= 0 && 5 + msgLen <= payload.size) {
                val protoBytes = payload.copyOfRange(5, 5 + msgLen)
                val fakeMsg = ProxyMessage(0, 0, expedition.registry.Direction.CLIENT_TO_UPSTREAM,
                    java.time.Instant.EPOCH, protoBytes)
                if (protobuf.supports(fakeMsg)) {
                    val rendered = protobuf.render(fakeMsg)
                    rendered.split("\n").forEach { line ->
                        sb.appendLine("grpc:$compressed $line")
                    }
                    return
                }
            }
        }
        sb.appendLine("hex:${payload.toHex()}")
    }

    private fun renderSettings(payload: ByteArray, sb: StringBuilder) {
        if (payload.size % 6 != 0) { sb.appendLine("hex:${payload.toHex()}"); return }
        val settingNames = mapOf(
            1 to "HEADER_TABLE_SIZE", 2 to "ENABLE_PUSH", 3 to "MAX_CONCURRENT_STREAMS",
            4 to "INITIAL_WINDOW_SIZE", 5 to "MAX_FRAME_SIZE", 6 to "MAX_HEADER_LIST_SIZE",
        )
        var pos = 0
        while (pos + 6 <= payload.size) {
            val id = ((payload[pos].toInt() and 0xff) shl 8) or (payload[pos + 1].toInt() and 0xff)
            val value = ((payload[pos + 2].toInt() and 0xff).toLong() shl 24) or
                        ((payload[pos + 3].toInt() and 0xff).toLong() shl 16) or
                        ((payload[pos + 4].toInt() and 0xff).toLong() shl 8) or
                         (payload[pos + 5].toInt() and 0xff).toLong()
            val name = settingNames[id] ?: "UNKNOWN($id)"
            sb.appendLine("  $name = $value")
            pos += 6
        }
    }

    private fun renderGoaway(payload: ByteArray, sb: StringBuilder) {
        if (payload.size < 8) { sb.appendLine("hex:${payload.toHex()}"); return }
        val lastStreamId = ((payload[0].toInt() and 0x7f) shl 24) or
                           ((payload[1].toInt() and 0xff) shl 16) or
                           ((payload[2].toInt() and 0xff) shl 8) or
                            (payload[3].toInt() and 0xff)
        val errorCode = ((payload[4].toInt() and 0xff).toLong() shl 24) or
                        ((payload[5].toInt() and 0xff).toLong() shl 16) or
                        ((payload[6].toInt() and 0xff).toLong() shl 8) or
                         (payload[7].toInt() and 0xff).toLong()
        sb.appendLine("  last_stream=$lastStreamId error=$errorCode")
        if (payload.size > 8) {
            sb.appendLine("  debug:${String(payload, 8, payload.size - 8, Charsets.ISO_8859_1)}")
        }
    }

    private fun renderWindowUpdate(payload: ByteArray, sb: StringBuilder) {
        if (payload.size < 4) { sb.appendLine("hex:${payload.toHex()}"); return }
        val increment = ((payload[0].toInt() and 0x7f) shl 24) or
                        ((payload[1].toInt() and 0xff) shl 16) or
                        ((payload[2].toInt() and 0xff) shl 8) or
                         (payload[3].toInt() and 0xff)
        sb.appendLine("  increment=$increment")
    }

    // ── Parse-edit helpers ──────────────────────────────────────────────

    private data class FrameHeader(val type: Int, val flags: Int, val streamId: Int)

    private fun parseFrameHeader(line: String): FrameHeader? {
        // [TYPE stream=N flags=XX ...]
        val inner = line.removePrefix("[").removeSuffix("]").trim()
        val parts = inner.split("\\s+".toRegex())
        if (parts.isEmpty()) return null
        val typeName = parts[0]
        val type = FRAME_TYPES.entries.firstOrNull { it.value == typeName }?.key ?: return null
        var streamId = 0
        var flags = 0
        for (p in parts.drop(1)) {
            when {
                p.startsWith("stream=") -> streamId = p.removePrefix("stream=").toIntOrNull() ?: 0
                p.startsWith("flags=") -> flags = p.removePrefix("flags=").toIntOrNull(16) ?: 0
            }
        }
        return FrameHeader(type, flags, streamId)
    }

    private fun encodePayload(frameType: Int, lines: List<String>): ByteArray {
        if (lines.isEmpty()) return byteArrayOf()
        // DATA frames with grpc: prefix → re-encode through protobuf + gRPC framing
        if (frameType == 0 && lines.any { it.trim().startsWith("grpc:") }) {
            return encodeGrpcData(lines)
        }
        // Everything else: raw hex or settings (just use hex for round-trip)
        val hexLines = lines.filter { it.trim().startsWith("hex:") }
        if (hexLines.isNotEmpty()) {
            return hexToBytes(hexLines.joinToString("") { it.trim().removePrefix("hex:") })
        }
        // Settings/goaway/window-update: pass through as empty (not editable)
        return byteArrayOf()
    }

    private fun encodeGrpcData(lines: List<String>): ByteArray {
        val protoLines = ArrayList<String>()
        var compressed = 0
        for (line in lines) {
            val trimmed = line.trim()
            if (!trimmed.startsWith("grpc:")) continue
            // "grpc:0 1 varint 42" → compressed=0, proto line="1 varint 42"
            val afterPrefix = trimmed.removePrefix("grpc:")
            val spaceIdx = afterPrefix.indexOf(' ')
            if (spaceIdx > 0) {
                compressed = afterPrefix.substring(0, spaceIdx).toIntOrNull() ?: 0
                protoLines.add(afterPrefix.substring(spaceIdx + 1))
            }
        }
        val protoEdit = protoLines.joinToString("\n")
        val fakeOriginal = ProxyMessage(0, 0, expedition.registry.Direction.CLIENT_TO_UPSTREAM,
            java.time.Instant.EPOCH, byteArrayOf())
        val protoBytes = protobuf.parseEdit(protoEdit, fakeOriginal)
        // gRPC framing: 1 byte compressed + 4 byte BE length + protobuf
        val out = ByteArray(5 + protoBytes.size)
        out[0] = compressed.toByte()
        val len = protoBytes.size
        out[1] = ((len shr 24) and 0xff).toByte()
        out[2] = ((len shr 16) and 0xff).toByte()
        out[3] = ((len shr 8) and 0xff).toByte()
        out[4] = (len and 0xff).toByte()
        System.arraycopy(protoBytes, 0, out, 5, protoBytes.size)
        return out
    }
}
