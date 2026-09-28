package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * Text / line-oriented protocol dissector — one dissector that makes any mostly-
 * printable protocol (SMTP, FTP, IRC, POP3/IMAP, HTTP, memcached, STOMP, …)
 * readable and editable instead of raw hex. Renders the bytes as text and
 * re-encodes the edited text faithfully (latin-1, so every byte round-trips).
 * Ranked below the binary dissectors (Redis), above the hex fallback.
 */
class LineProtocolDissector : Dissector {

    override fun supports(message: ProxyMessage): Boolean {
        val b = message.rawBytes
        if (b.isEmpty()) return false
        var printable = 0
        for (x in b) {
            val c = x.toInt() and 0xff
            if (c == 0) return false                                   // NUL -> binary
            if (c in 0x20..0x7e || c == 0x09 || c == 0x0a || c == 0x0d) printable++
        }
        return printable.toDouble() / b.size >= 0.90                   // mostly text
    }

    override fun render(message: ProxyMessage): String =
        String(message.rawBytes, Charsets.ISO_8859_1)

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray =
        edited.toByteArray(Charsets.ISO_8859_1)
}
