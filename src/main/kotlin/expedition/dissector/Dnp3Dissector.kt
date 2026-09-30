package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * DNP3 dissector. Decodes the data-link header (0x0564 start, length, control, destination,
 * source) into a readable summary; the transport/application layers are shown as raw hex and
 * edits round-trip via the `raw: hex:` line.
 *
 * NOTE: data-link header only; CRCs are not validated or recomputed (raw-hex round-trip).
 */
class Dnp3Dissector : Dissector {

    private data class Header(val length: Int, val control: Int, val dst: Int, val src: Int)

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val h = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        return "DNP3 len=${h.length} ctrl=0x%02x dst=${h.dst} src=${h.src}\nraw: hex:%s"
            .format(h.control, message.rawBytes.toHex())
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val rawLine = edited.split("\n").map { it.trim() }
            .firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private fun parse(bytes: ByteArray): Header? {
        if (bytes.size < 10) return null
        if (bytes[0].toInt() and 0xff != 0x05 || bytes[1].toInt() and 0xff != 0x64) return null
        val length = bytes[2].toInt() and 0xff
        val control = bytes[3].toInt() and 0xff
        val dst = (bytes[4].toInt() and 0xff) or ((bytes[5].toInt() and 0xff) shl 8) // little-endian
        val src = (bytes[6].toInt() and 0xff) or ((bytes[7].toInt() and 0xff) shl 8)
        if (length < 5) return null
        return Header(length, control, dst, src)
    }


}
