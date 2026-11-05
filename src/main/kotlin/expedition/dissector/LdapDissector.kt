package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * LDAP message dissector (RFC 4511), BER/DER-encoded ASN.1.
 *
 * An LDAPMessage is a BER SEQUENCE (tag 0x30) of: messageID (INTEGER, tag 0x02) followed by a
 * protocolOp whose leading tag byte is an APPLICATION-class tag identifying the operation
 * (0x60 bindRequest, 0x61 bindResponse, 0x63 searchRequest, 0x64 searchResultEntry,
 * 0x65 searchResultDone, 0x42 unbindRequest, ...).
 *
 * supports() validates that structure (SEQUENCE tag + consistent length, a valid INTEGER
 * messageID, and a recognised protocolOp application tag) so it stays specific and does not
 * steal other length-prefixed binary protocols.
 *
 * Security testing value: LDAP bind credential capture, anonymous/unauthenticated bind
 * detection, and search-filter injection review.
 */
class LdapDissector : Dissector {

    companion object {
        // protocolOp leading tag byte -> operation name (RFC 4511 APPLICATION tags).
        private val OP_NAMES = mapOf(
            0x60 to "bindRequest",            // [APPLICATION 0] constructed
            0x61 to "bindResponse",           // [APPLICATION 1]
            0x42 to "unbindRequest",          // [APPLICATION 2] primitive
            0x63 to "searchRequest",          // [APPLICATION 3]
            0x64 to "searchResultEntry",      // [APPLICATION 4]
            0x65 to "searchResultDone",       // [APPLICATION 5]
            0x66 to "modifyRequest",          // [APPLICATION 6]
            0x67 to "modifyResponse",         // [APPLICATION 7]
            0x68 to "addRequest",             // [APPLICATION 8]
            0x69 to "addResponse",            // [APPLICATION 9]
            0x4A to "delRequest",             // [APPLICATION 10] primitive
            0x6A to "delResponse",            // [APPLICATION 10]
            0x6B to "modifyDNRequest",        // [APPLICATION 11]
            0x6C to "modifyDNResponse",       // [APPLICATION 12]
            0x6D to "compareRequest",         // [APPLICATION 13]
            0x6E to "compareResponse",        // [APPLICATION 14]
            0x50 to "abandonRequest",         // [APPLICATION 16] primitive
            0x73 to "searchResultReference",  // [APPLICATION 19]
            0x77 to "extendedRequest",        // [APPLICATION 23]
            0x78 to "extendedResponse",       // [APPLICATION 24]
            0x79 to "intermediateResponse",   // [APPLICATION 25]
        )

        private const val TAG_SEQUENCE = 0x30
        private const val TAG_INTEGER = 0x02
        private const val TAG_OCTET_STRING = 0x04
    }

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val sb = StringBuilder()
        sb.append("LDAP ${p.opName}  messageID=${p.messageID}")

        // Best-effort extra fields for bindRequest: version INTEGER then the bind DN (OCTET STRING).
        if (p.opTag == 0x60) {
            var pos = p.opContentStart
            val end = p.opContentStart + p.opContentLen
            val version = readTlv(message.rawBytes, pos, end)
            if (version != null && version.tag == TAG_INTEGER) {
                sb.append("  version=${intValue(message.rawBytes, version)}")
                pos = version.next
                val name = readTlv(message.rawBytes, pos, end)
                if (name != null && name.tag == TAG_OCTET_STRING) {
                    val dn = String(message.rawBytes, name.contentStart, name.contentLen, Charsets.UTF_8)
                    sb.append("  dn=\"$dn\"")
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

    private data class Parsed(
        val messageID: Long,
        val opTag: Int,
        val opName: String,
        val opContentStart: Int,
        val opContentLen: Int,
    )

    /** A single BER TLV: its tag, where its content begins/ends, and the offset of the next element. */
    private data class Tlv(val tag: Int, val contentStart: Int, val contentLen: Int, val next: Int)

    private fun parse(bytes: ByteArray): Parsed? {
        if (bytes.size < 2) return null
        if ((bytes[0].toInt() and 0xff) != TAG_SEQUENCE) return null

        val seq = readLen(bytes, 1) ?: return null
        val contentStart = seq.headerEnd
        val seqEnd = contentStart + seq.length
        // Message must fit the buffer; trailing bytes after the SEQUENCE are tolerated.
        if (seqEnd > bytes.size) return null

        // messageID: INTEGER
        val idTlv = readTlv(bytes, contentStart, seqEnd) ?: return null
        if (idTlv.tag != TAG_INTEGER) return null
        if (idTlv.contentLen < 1 || idTlv.contentLen > 4) return null

        // protocolOp: an APPLICATION-tagged element with a known operation tag.
        val opStart = idTlv.next
        if (opStart >= seqEnd) return null
        val opTag = bytes[opStart].toInt() and 0xff
        val opName = OP_NAMES[opTag] ?: return null
        val opTlv = readTlv(bytes, opStart, seqEnd) ?: return null

        return Parsed(intValue(bytes, idTlv), opTag, opName, opTlv.contentStart, opTlv.contentLen)
    }

    /** Reads a TLV starting at [pos], bounded by [end] (exclusive). Returns null if it doesn't fit. */
    private fun readTlv(bytes: ByteArray, pos: Int, end: Int): Tlv? {
        if (pos < 0 || pos + 1 >= end) return null
        val tag = bytes[pos].toInt() and 0xff
        val len = readLen(bytes, pos + 1) ?: return null
        val contentStart = len.headerEnd
        val next = contentStart + len.length
        if (next > end) return null
        return Tlv(tag, contentStart, len.length, next)
    }

    private data class Len(val length: Int, val headerEnd: Int)

    /**
     * Minimal BER length reader at offset [i]. Short form (high bit clear) is a 1-byte length;
     * long form's low 7 bits give the number of big-endian length bytes that follow. Indefinite
     * form and absurdly long lengths (> 4 bytes) are rejected.
     */
    private fun readLen(bytes: ByteArray, i: Int): Len? {
        if (i >= bytes.size) return null
        val first = bytes[i].toInt() and 0xff
        if (first < 0x80) return Len(first, i + 1)
        val n = first and 0x7f
        if (n == 0 || n > 4) return null // indefinite form unsupported; cap width
        if (i + 1 + n > bytes.size) return null
        var len = 0L
        for (k in 0 until n) len = (len shl 8) or (bytes[i + 1 + k].toLong() and 0xff)
        if (len < 0 || len > Int.MAX_VALUE) return null
        return Len(len.toInt(), i + 1 + n)
    }

    private fun intValue(bytes: ByteArray, tlv: Tlv): Long {
        var v = 0L
        for (k in 0 until tlv.contentLen) v = (v shl 8) or (bytes[tlv.contentStart + k].toLong() and 0xff)
        return v
    }
}
