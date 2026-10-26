package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * QUIC packet dissector — parses Long Header Initial/Handshake packets (RFC 9000)
 * and extracts the TLS ClientHello SNI from the CRYPTO frame in Initial packets.
 *
 * Limitations (by design):
 * - Initial packet payloads are protected with keys derived from the DCID. This
 *   dissector does NOT decrypt the payload — it parses the unprotected header fields
 *   (version, DCID, SCID, token, length) and attempts to find a plaintext ClientHello
 *   in the first CRYPTO frame of Initial packets (some implementations send the
 *   ClientHello unencrypted in the first flight; when encrypted, we show "encrypted").
 * - Short Header (1-RTT) packets are shown as opaque with the DCID prefix.
 * - No QUIC proxy / decrypt / re-encrypt — that requires a full QUIC stack.
 *
 * Security testing value: protocol detection (is this QUIC?), version fingerprinting,
 * SNI extraction for target mapping, connection ID tracking.
 */
class QuicDissector : Dissector {

    companion object {
        private val KNOWN_VERSIONS = mapOf(
            0x00000001 to "v1 (RFC 9000)",
            0x6B3343CF.toInt() to "v2 (RFC 9369)",
            0xFF000020.toInt() to "draft-32",
            0xFF00001D.toInt() to "draft-29",
        )
        private val LONG_HEADER_TYPES = mapOf(
            0x00 to "Initial",
            0x01 to "0-RTT",
            0x02 to "Handshake",
            0x03 to "Retry",
        )
    }

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val sb = StringBuilder()

        if (p.isLongHeader) {
            val typeName = LONG_HEADER_TYPES[p.longType] ?: "Type(${p.longType})"
            val versionName = KNOWN_VERSIONS[p.version] ?: "0x%08x".format(p.version)
            sb.append("QUIC $typeName  version=$versionName")
            sb.append("\n  DCID: ${p.dcid}  (${p.dcidLen}B)")
            sb.append("\n  SCID: ${p.scid}  (${p.scidLen}B)")
            if (p.tokenLen > 0) {
                sb.append("\n  Token: ${p.token} (${p.tokenLen}B)")
            }
            sb.append("\n  Payload length: ${p.payloadLen}B")
            if (p.sni.isNotEmpty()) {
                sb.append("\n  SNI: ${p.sni}")
            }
            if (p.alpn.isNotEmpty()) {
                sb.append("\n  ALPN: ${p.alpn.joinToString(", ")}")
            }
            if (p.longType == 0x00 && p.sni.isEmpty()) {
                sb.append("\n  ClientHello: encrypted or not found")
            }
        } else {
            sb.append("QUIC Short Header (1-RTT)")
            if (p.dcid.isNotEmpty()) {
                sb.append("\n  DCID prefix: ${p.dcid}")
            }
            sb.append("\n  Payload: ${message.rawBytes.size - 1 - p.dcidLen}B (encrypted)")
        }

        sb.append("\n  Total: ${message.rawBytes.size}B")
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
        val isLongHeader: Boolean,
        val longType: Int = 0,
        val version: Int = 0,
        val dcidLen: Int = 0,
        val dcid: String = "",
        val scidLen: Int = 0,
        val scid: String = "",
        val tokenLen: Int = 0,
        val token: String = "",
        val payloadLen: Int = 0,
        val sni: String = "",
        val alpn: List<String> = emptyList(),
    )

    private fun parse(bytes: ByteArray): Parsed? {
        if (bytes.size < 5) return null
        val first = bytes[0].toInt() and 0xff

        // Long Header: bit 7 = 1, bit 6 = 1 (fixed)
        if (first and 0x80 != 0) {
            if (first and 0x40 == 0) return null // fixed bit must be 1
            val longType = (first shr 4) and 0x03
            if (bytes.size < 7) return null
            val version = i32(bytes, 1)
            // Version 0 is version negotiation — special case
            if (version == 0 && longType == 0) {
                // Version Negotiation: just parse DCID/SCID
                return parseVersionNeg(bytes)
            }
            // Validate it looks like QUIC
            if (!KNOWN_VERSIONS.containsKey(version) && version != 0) {
                // Accept unknown versions only if they look plausible
                if (version and 0x0F0F0F0F == 0x0A0A0A0A) return null // GREASE
            }

            val dcidLen = bytes[5].toInt() and 0xff
            if (dcidLen > 20 || 6 + dcidLen >= bytes.size) return null
            val dcid = bytes.copyOfRange(6, 6 + dcidLen).toHex()

            val scidOff = 6 + dcidLen
            if (scidOff >= bytes.size) return null
            val scidLen = bytes[scidOff].toInt() and 0xff
            if (scidLen > 20 || scidOff + 1 + scidLen > bytes.size) return null
            val scid = bytes.copyOfRange(scidOff + 1, scidOff + 1 + scidLen).toHex()

            var pos = scidOff + 1 + scidLen
            var tokenLen = 0
            var token = ""

            // Initial packets have a token length field
            if (longType == 0x00) {
                val (tl, tlBytes) = readVarInt(bytes, pos) ?: return null
                tokenLen = tl.toInt()
                pos += tlBytes
                if (pos + tokenLen > bytes.size) return null
                if (tokenLen > 0) {
                    token = bytes.copyOfRange(pos, pos + tokenLen).toHex()
                    pos += tokenLen
                }
            }

            // Payload length (variable-length integer)
            val (payloadLen, plBytes) = readVarInt(bytes, pos) ?: return null
            pos += plBytes

            // Try to extract SNI from the payload (if it contains a visible ClientHello)
            var sni = ""
            var alpn = emptyList<String>()
            if (longType == 0x00 && pos + payloadLen.toInt() <= bytes.size) {
                val payload = bytes.copyOfRange(pos, minOf(pos + payloadLen.toInt(), bytes.size))
                val ch = findClientHello(payload)
                if (ch != null) {
                    sni = ch.first
                    alpn = ch.second
                }
            }

            return Parsed(
                isLongHeader = true, longType = longType, version = version,
                dcidLen = dcidLen, dcid = dcid, scidLen = scidLen, scid = scid,
                tokenLen = tokenLen, token = token, payloadLen = payloadLen.toInt(),
                sni = sni, alpn = alpn,
            )
        }

        // Short Header: bit 7 = 0, bit 6 = 1
        if (first and 0x40 == 0) return null
        // We don't know the DCID length for Short Headers without connection state.
        // Show first 8 bytes as a guess (most implementations use 8-byte CIDs).
        val dcidLen = minOf(8, bytes.size - 1)
        val dcid = bytes.copyOfRange(1, 1 + dcidLen).toHex()
        return Parsed(isLongHeader = false, dcidLen = dcidLen, dcid = dcid)
    }

    private fun parseVersionNeg(bytes: ByteArray): Parsed? {
        if (bytes.size < 7) return null
        val dcidLen = bytes[5].toInt() and 0xff
        if (6 + dcidLen >= bytes.size) return null
        val dcid = bytes.copyOfRange(6, 6 + dcidLen).toHex()
        val scidOff = 6 + dcidLen
        if (scidOff >= bytes.size) return null
        val scidLen = bytes[scidOff].toInt() and 0xff
        if (scidOff + 1 + scidLen > bytes.size) return null
        val scid = bytes.copyOfRange(scidOff + 1, scidOff + 1 + scidLen).toHex()
        return Parsed(isLongHeader = true, longType = 0, version = 0,
            dcidLen = dcidLen, dcid = dcid, scidLen = scidLen, scid = scid)
    }

    /**
     * Scan the payload for a TLS ClientHello and extract SNI + ALPN.
     * The payload may be packet-number-encrypted in real QUIC — this only works
     * when the ClientHello bytes appear in plaintext (some test tools, or after
     * removing Initial protection with the DCID-derived key).
     */
    private fun findClientHello(payload: ByteArray): Pair<String, List<String>>? {
        // Scan for TLS Handshake ClientHello marker: 0x01 followed by 3-byte length
        for (i in 0 until payload.size - 40) {
            if (payload[i].toInt() and 0xff != 0x01) continue
            val hsLen = ((payload.getOrNull(i+1)?.toInt()?.and(0xff) ?: continue) shl 16) or
                        ((payload.getOrNull(i+2)?.toInt()?.and(0xff) ?: continue) shl 8) or
                        (payload.getOrNull(i+3)?.toInt()?.and(0xff) ?: continue)
            if (hsLen < 35 || hsLen > 16384) continue
            // Check for TLS 1.3 version (0x0303 at offset +4)
            val major = payload.getOrNull(i+4)?.toInt()?.and(0xff) ?: continue
            val minor = payload.getOrNull(i+5)?.toInt()?.and(0xff) ?: continue
            if (major != 0x03 || minor !in 0x01..0x03) continue
            // This looks like a ClientHello — scan extensions for SNI and ALPN
            return extractSniAlpn(payload, i, minOf(i + 4 + hsLen, payload.size))
        }
        return null
    }

    private fun extractSniAlpn(payload: ByteArray, start: Int, end: Int): Pair<String, List<String>>? {
        var sni = ""
        val alpn = mutableListOf<String>()
        // Skip to extensions: ClientHello = version(2) + random(32) + session_id_len + ...
        var pos = start + 6 + 32 // past handshake header + version + random
        if (pos >= end) return null
        val sidLen = payload.getOrNull(pos)?.toInt()?.and(0xff) ?: return null
        pos += 1 + sidLen
        if (pos + 2 > end) return null
        val csLen = u16(payload, pos); pos += 2 + csLen
        if (pos >= end) return null
        val compLen = payload[pos].toInt() and 0xff; pos += 1 + compLen
        if (pos + 2 > end) return null
        val extLen = u16(payload, pos); pos += 2
        val extEnd = minOf(pos + extLen, end)
        while (pos + 4 <= extEnd) {
            val extType = u16(payload, pos)
            val extDataLen = u16(payload, pos + 2)
            pos += 4
            if (pos + extDataLen > extEnd) break
            when (extType) {
                0x0000 -> { // SNI
                    if (extDataLen > 5) {
                        val nameLen = u16(payload, pos + 3)
                        if (pos + 5 + nameLen <= extEnd) {
                            sni = String(payload, pos + 5, nameLen, Charsets.US_ASCII)
                        }
                    }
                }
                0x0010 -> { // ALPN
                    if (extDataLen > 2) {
                        var ap = pos + 2
                        val apEnd = pos + extDataLen
                        while (ap < apEnd) {
                            val pLen = payload[ap].toInt() and 0xff; ap++
                            if (ap + pLen <= apEnd) {
                                alpn.add(String(payload, ap, pLen, Charsets.US_ASCII))
                            }
                            ap += pLen
                        }
                    }
                }
            }
            pos += extDataLen
        }
        return if (sni.isNotEmpty() || alpn.isNotEmpty()) Pair(sni, alpn) else null
    }

    /** Read a QUIC variable-length integer (RFC 9000 §16). Returns (value, bytesConsumed). */
    private fun readVarInt(bytes: ByteArray, offset: Int): Pair<Long, Int>? {
        if (offset >= bytes.size) return null
        val first = bytes[offset].toInt() and 0xff
        val len = 1 shl (first shr 6)
        if (offset + len > bytes.size) return null
        var value = (first and 0x3f).toLong()
        for (i in 1 until len) {
            value = (value shl 8) or (bytes[offset + i].toInt() and 0xff).toLong()
        }
        return Pair(value, len)
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
    private fun i32(b: ByteArray, i: Int) =
        ((b[i].toInt() and 0xff) shl 24) or ((b[i+1].toInt() and 0xff) shl 16) or
        ((b[i+2].toInt() and 0xff) shl 8) or (b[i+3].toInt() and 0xff)
}
