package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * Heuristic Protobuf wire-format dissector — decodes without a `.proto` definition
 * (like NCC's blackboxprotobuf), for the common case of binary/gRPC payloads flowing
 * over a raw TCP relay.
 *
 * Editable text format, one top-level field per line, round-trippable:
 *   `<field_number> <wire_type> <value>`
 *   - `varint <decimal>`
 *   - `i32 0x<8 hex>`   (raw little-endian wire bytes)
 *   - `i64 0x<16 hex>`  (raw little-endian wire bytes)
 *   - `len str:<text>`  (all-printable payloads) or `len hex:<hex>`
 *
 * NOTE: length-delimited fields are kept flat (str/hex) rather than recursed into
 * nested messages, so the edit round-trip is unambiguous. Group wire types (3/4,
 * deprecated) are treated as unsupported. Non-canonical varints won't round-trip
 * byte-identically — acceptable for the wire data we target.
 */
class ProtobufDissector : Dissector {

    private data class Field(val number: Int, val wireType: Int, val value: ByteArray)

    override fun supports(message: ProxyMessage): Boolean {
        val fields = tryParse(message.rawBytes) ?: return false
        return fields.isNotEmpty()
    }

    override fun render(message: ProxyMessage): String {
        val fields = tryParse(message.rawBytes) ?: return HexStringDissector().render(message)
        return fields.joinToString("\n") { renderField(it) }
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val out = ArrayList<Byte>()
        for (rawLine in edited.split("\n")) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            encodeField(line, out)
        }
        return out.toByteArray()
    }

    private fun renderField(f: Field): String = when (f.wireType) {
        0 -> "${f.number} varint ${decodeVarint(f.value, 0).first}"
        1 -> "${f.number} i64 0x${f.value.toHex()}"
        5 -> "${f.number} i32 0x${f.value.toHex()}"
        2 -> if (f.value.all { it in 0x20..0x7e || it == 0x09.toByte() })
            "${f.number} len str:${String(f.value, Charsets.ISO_8859_1)}"
        else
            "${f.number} len hex:${f.value.toHex()}"
        else -> "${f.number} unknown hex:${f.value.toHex()}"
    }

    private fun encodeField(line: String, out: ArrayList<Byte>) {
        // "<field> <type> <value...>" — value may contain spaces (str:), so split into 3.
        val parts = line.split(" ", limit = 3)
        require(parts.size >= 3) { "Malformed protobuf field line: $line" }
        val fieldNumber = parts[0].toInt()
        val type = parts[1]
        val value = parts[2]
        when (type) {
            "varint" -> {
                writeVarint((fieldNumber.toLong() shl 3) or 0, out)
                writeVarint(value.toLong(), out)
            }
            "i64" -> {
                writeVarint((fieldNumber.toLong() shl 3) or 1, out)
                out.addAll(hexToBytes(value.removePrefix("0x")).toList())
            }
            "i32" -> {
                writeVarint((fieldNumber.toLong() shl 3) or 5, out)
                out.addAll(hexToBytes(value.removePrefix("0x")).toList())
            }
            "len" -> {
                writeVarint((fieldNumber.toLong() shl 3) or 2, out)
                val bytes = when {
                    value.startsWith("str:") -> value.removePrefix("str:").toByteArray(Charsets.ISO_8859_1)
                    value.startsWith("hex:") -> hexToBytes(value.removePrefix("hex:"))
                    else -> error("len value must be str: or hex:")
                }
                writeVarint(bytes.size.toLong(), out)
                out.addAll(bytes.toList())
            }
            else -> error("Unknown wire type keyword: $type")
        }
    }

    /** Returns the parsed top-level fields, or null if the bytes are not valid protobuf. */
    private fun tryParse(bytes: ByteArray): List<Field>? {
        if (bytes.isEmpty()) return null
        val fields = ArrayList<Field>()
        var pos = 0
        while (pos < bytes.size) {
            val (tag, tagLen) = try { decodeVarint(bytes, pos) } catch (e: Exception) { return null }
            pos += tagLen
            val fieldNumber = (tag ushr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (fieldNumber == 0) return null
            when (wireType) {
                0 -> {
                    val start = pos
                    val (_, len) = try { decodeVarint(bytes, pos) } catch (e: Exception) { return null }
                    pos += len
                    fields.add(Field(fieldNumber, 0, bytes.copyOfRange(start, pos)))
                }
                1 -> {
                    if (pos + 8 > bytes.size) return null
                    fields.add(Field(fieldNumber, 1, bytes.copyOfRange(pos, pos + 8)))
                    pos += 8
                }
                5 -> {
                    if (pos + 4 > bytes.size) return null
                    fields.add(Field(fieldNumber, 5, bytes.copyOfRange(pos, pos + 4)))
                    pos += 4
                }
                2 -> {
                    val (length, lenLen) = try { decodeVarint(bytes, pos) } catch (e: Exception) { return null }
                    pos += lenLen
                    val end = pos + length.toInt()
                    if (length < 0 || end > bytes.size) return null
                    fields.add(Field(fieldNumber, 2, bytes.copyOfRange(pos, end)))
                    pos = end
                }
                else -> return null // wire types 3,4 (groups) and 6,7 (invalid)
            }
        }
        return fields
    }

    /** Decodes a base-128 varint at [offset]; returns (value, bytesConsumed). */
    private fun decodeVarint(bytes: ByteArray, offset: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var i = offset
        while (true) {
            if (i >= bytes.size) throw IndexOutOfBoundsException("truncated varint")
            if (shift >= 64) throw ArithmeticException("varint too long")
            val b = bytes[i].toInt() and 0xff
            result = result or ((b.toLong() and 0x7f) shl shift)
            i++
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result to (i - offset)
    }

    private fun writeVarint(value: Long, out: ArrayList<Byte>) {
        var v = value
        while (true) {
            val b = (v and 0x7f).toInt()
            v = v ushr 7
            if (v != 0L) out.add((b or 0x80).toByte()) else { out.add(b.toByte()); break }
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
