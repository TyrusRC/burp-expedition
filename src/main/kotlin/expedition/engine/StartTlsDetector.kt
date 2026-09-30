package expedition.engine

/**
 * Detects a plaintext→TLS (STARTTLS) upgrade point on a relayed connection so the proxy
 * can MITM the subsequent TLS. Stateful, one instance per connection.
 *
 * Supports the common line-based mail dances — SMTP `STARTTLS`/`220`, POP3 `STLS`/`+OK`,
 * IMAP tagged `STARTTLS`/`<tag> OK` — and PostgreSQL's binary `SSLRequest`/`S`. The rule
 * is always: the client requests the upgrade, then the server's affirmative go-ahead is
 * the signal to insert TLS on both legs (after that response reaches the client).
 *
 * NOTE: detection only; wiring the SslHandlers on trigger is the listener's job. A
 * declined upgrade (SMTP 4xx/5xx, IMAP NO/BAD, POP3 -ERR, Postgres `N`) resets state.
 */
class StartTlsDetector {

    private var pendingText = false
    private var pendingPostgres = false

    private val pgSslRequest = byteArrayOf(0x00, 0x00, 0x00, 0x08, 0x04, 0xd2.toByte(), 0x16, 0x2f)

    /** Feed client→upstream bytes. Returns false (the trigger is the server's later go-ahead). */
    fun onClientData(bytes: ByteArray): Boolean {
        if (bytes.size == 8 && bytes.contentEquals(pgSslRequest)) {
            pendingPostgres = true
            return false
        }
        val text = String(bytes, Charsets.ISO_8859_1)
        val requested = text.lineSequence().any {
            val t = it.trim().uppercase()
            t == "STARTTLS" || t == "STLS" || t.endsWith(" STARTTLS") || t.endsWith(" STLS")
        }
        if (requested) pendingText = true
        return false
    }

    /** Feed upstream→client bytes. Returns true when the server's go-ahead confirms the upgrade. */
    fun onUpstreamData(bytes: ByteArray): Boolean {
        if (pendingPostgres) {
            pendingPostgres = false
            return bytes.isNotEmpty() && bytes[0] == 'S'.code.toByte()
        }
        if (pendingText) {
            pendingText = false
            val firstLine = String(bytes, Charsets.ISO_8859_1).lineSequence().firstOrNull()?.trim() ?: return false
            return firstLine.startsWith("220") ||
                firstLine.startsWith("+OK") ||
                Regex("^\\S+\\s+OK\\b", RegexOption.IGNORE_CASE).containsMatchIn(firstLine)
        }
        return false
    }
}
