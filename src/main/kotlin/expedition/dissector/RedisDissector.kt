package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * RESP (REdis Serialization Protocol) dissector — Redis is a prime non-HTTP
 * target Burp can't proxy. Renders a command array as an inline command line
 * (`SET key value`) and simple replies readably (`+OK`, `-ERR ...`, `:42`,
 * bulk strings); parseEdit re-encodes an edited inline command back to a RESP
 * array so the operator can tweak + resend (e.g. change a key, add `CONFIG GET *`).
 *
 * A line already starting with a RESP marker (`* + - : $`) is treated as raw
 * RESP (only CRLF-normalised), so a hand-written protocol line still round-trips.
 */
class RedisDissector : Dissector {

    override fun supports(message: ProxyMessage): Boolean {
        val b = message.rawBytes
        return b.isNotEmpty() && b[0].toInt().toChar() in "*+-:$"
    }

    override fun render(message: ProxyMessage): String {
        val s = String(message.rawBytes, Charsets.ISO_8859_1)
        return try {
            when (s.firstOrNull()) {
                '*' -> renderArray(s)
                '+' -> s.trimEnd('\r', '\n')                 // status: +OK
                '-' -> s.trimEnd('\r', '\n')                 // error: -ERR ...
                ':' -> "(integer) " + s.substring(1).trimEnd('\r', '\n')
                '$' -> renderBulk(s)
                else -> s
            }
        } catch (e: Exception) {
            s
        }
    }

    private fun renderArray(s: String): String {
        val lines = s.split("\r\n")
        val n = lines[0].substring(1).toIntOrNull() ?: return s
        val args = ArrayList<String>(n)
        var idx = 1
        repeat(n) {
            if (idx + 1 < lines.size && lines[idx].startsWith("$")) {
                args.add(lines[idx + 1]); idx += 2
            } else if (idx < lines.size) {
                args.add(lines[idx]); idx += 1
            }
        }
        return args.joinToString(" ")
    }

    private fun renderBulk(s: String): String {
        val lines = s.split("\r\n")
        return if (lines.size >= 2) lines[1] else s
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val trimmed = edited.trimEnd('\r', '\n')
        // Raw RESP line kept as-is (normalise LF -> CRLF so it's wire-correct).
        if (trimmed.firstOrNull() in listOf('*', '+', '-', ':', '$')) {
            return (trimmed.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n")
                .toByteArray(Charsets.ISO_8859_1)
        }
        // Inline command -> RESP array.
        val args = trimmed.split(Regex("\\s+")).filter { it.isNotEmpty() }
        val sb = StringBuilder().append("*").append(args.size).append("\r\n")
        for (a in args) sb.append("$").append(a.toByteArray(Charsets.ISO_8859_1).size)
            .append("\r\n").append(a).append("\r\n")
        return sb.toString().toByteArray(Charsets.ISO_8859_1)
    }
}
