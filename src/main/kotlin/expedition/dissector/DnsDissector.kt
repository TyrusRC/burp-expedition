package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * DNS message dissector (RFC 1035). Decodes the header and question section into a
 * readable summary; answers are summarised by count. Handles both UDP-style messages
 * and TCP-style messages with a 2-byte length prefix.
 *
 * NOTE: name compression makes a structured byte-exact re-encode fragile, so edits
 * round-trip through the appended `raw: hex:` line rather than by re-serialising the
 * decoded view. The decoded view is for understanding; the hex line is the source of truth.
 */
class DnsDissector : Dissector {

    private val typeNames = mapOf(
        1 to "A", 2 to "NS", 5 to "CNAME", 6 to "SOA", 12 to "PTR", 15 to "MX",
        16 to "TXT", 28 to "AAAA", 33 to "SRV", 255 to "ANY"
    )
    private val classNames = mapOf(1 to "IN", 3 to "CH", 4 to "HS", 255 to "ANY")

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val parsed = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val h = parsed.header
        val qr = (h.flags shr 15) and 1
        val opcode = (h.flags shr 11) and 0xf
        val rd = (h.flags shr 8) and 1
        val rcode = h.flags and 0xf
        val kind = if (qr == 0) "query" else "response"
        val sb = StringBuilder()
        sb.append("DNS $kind id=0x%04x flags=0x%04x (QR=$qr Opcode=$opcode RD=$rd RCODE=$rcode) "
            .format(h.id, h.flags))
        sb.append("qd=${h.qd} an=${h.an} ns=${h.ns} ar=${h.ar}")
        for (q in parsed.questions) {
            val t = typeNames[q.type] ?: "TYPE${q.type}"
            val c = classNames[q.klass] ?: "CLASS${q.klass}"
            sb.append("\nQ: ${q.name} $t $c")
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

    private data class Header(val id: Int, val flags: Int, val qd: Int, val an: Int, val ns: Int, val ar: Int)
    private data class Question(val name: String, val type: Int, val klass: Int)
    private data class Parsed(val header: Header, val questions: List<Question>)

    private fun parse(input: ByteArray): Parsed? {
        // TCP framing: a 2-byte length prefix equal to the rest of the buffer.
        val bytes = if (input.size > 2) {
            val prefixed = ((input[0].toInt() and 0xff) shl 8) or (input[1].toInt() and 0xff)
            if (prefixed == input.size - 2) input.copyOfRange(2, input.size) else input
        } else input
        if (bytes.size < 12) return null

        fun u16(i: Int) = ((bytes[i].toInt() and 0xff) shl 8) or (bytes[i + 1].toInt() and 0xff)
        val header = Header(u16(0), u16(2), u16(4), u16(6), u16(8), u16(10))
        // Plausibility bounds — keeps arbitrary binary from matching.
        if (header.qd !in 1..50 || header.an > 100 || header.ns > 100 || header.ar > 100) return null

        var pos = 12
        val questions = ArrayList<Question>()
        repeat(header.qd) {
            val labels = ArrayList<String>()
            while (true) {
                if (pos >= bytes.size) return null
                val len = bytes[pos].toInt() and 0xff
                if (len == 0) { pos++; break }
                if (len and 0xc0 != 0) return null // compression pointer in a question — unusual, bail
                if (pos + 1 + len > bytes.size) return null
                labels.add(String(bytes, pos + 1, len, Charsets.US_ASCII))
                pos += 1 + len
            }
            if (pos + 4 > bytes.size) return null
            val type = u16(pos); val klass = u16(pos + 2); pos += 4
            questions.add(Question(labels.joinToString("."), type, klass))
        }
        return Parsed(header, questions)
    }


}
