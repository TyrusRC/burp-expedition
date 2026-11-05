package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * TLS handshake dissector — parses a TLS record carrying a ClientHello or ServerHello
 * (the plaintext handshake that precedes key exchange) and surfaces the fields most
 * useful for a proxy: negotiated/offered versions, SNI, ALPN, and cipher suites.
 *
 * Scope (by design):
 * - Reads only the first record's ClientHello/ServerHello. Does not decrypt application
 *   data or follow a handshake split across records — Expedition terminates TLS itself
 *   (TcpTlsSupport), so the decrypted payload is dissected by the other dissectors; this
 *   one is for the brief plaintext handshake seen on a non-MITM (pass-through) listener
 *   or when inspecting a raw capture.
 * - No re-encode: parseEdit round-trips the raw bytes (hex), like the other binary
 *   dissectors — editing a handshake in flight is out of scope.
 *
 * Security-testing value: target mapping by SNI, ALPN/version/cipher fingerprinting,
 * spotting weak cipher suites or SNI-less (direct-IP) connections.
 */
class TlsDissector : Dissector {

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val sb = StringBuilder()
        sb.append("TLS ${p.handshakeName}  record=${versionName(p.recordVersion)}  offered=${versionName(p.helloVersion)}")
        if (p.sni.isNotEmpty()) sb.append("\n  SNI: ${p.sni}")
        if (p.alpn.isNotEmpty()) sb.append("\n  ALPN: ${p.alpn.joinToString(", ")}")
        if (p.supportedVersions.isNotEmpty())
            sb.append("\n  supported_versions: ${p.supportedVersions.joinToString(", ") { versionName(it) }}")
        if (p.cipherSuites.isNotEmpty()) {
            val label = if (p.isServerHello) "  selected cipher" else "  cipher suites (${p.cipherSuites.size})"
            sb.append("\n$label: ${p.cipherSuites.joinToString(", ") { cipherName(it) }}")
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
        val isServerHello: Boolean,
        val recordVersion: Int,
        val helloVersion: Int,
        val sni: String = "",
        val alpn: List<String> = emptyList(),
        val cipherSuites: List<Int> = emptyList(),
        val supportedVersions: List<Int> = emptyList(),
    ) {
        val handshakeName: String get() = if (isServerHello) "ServerHello" else "ClientHello"
    }

    private fun parse(b: ByteArray): Parsed? {
        // Record: content_type(1)=22 handshake, version(2), length(2)
        if (b.size < 9) return null
        if ((b[0].toInt() and 0xff) != 0x16) return null
        if ((b[1].toInt() and 0xff) != 0x03) return null
        if ((b[2].toInt() and 0xff) !in 0x00..0x04) return null
        val recordVersion = u16(b, 1)
        val recordLen = u16(b, 3)
        if (recordLen < 4) return null

        // Handshake: type(1), length(3), then ClientHello/ServerHello body
        val hsType = b[5].toInt() and 0xff
        val isServer = when (hsType) {
            0x01 -> false
            0x02 -> true
            else -> return null
        }
        val hsLen = ((b[6].toInt() and 0xff) shl 16) or ((b[7].toInt() and 0xff) shl 8) or (b[8].toInt() and 0xff)
        if (hsLen < 38) return null                 // version(2)+random(32)+sid_len(1)+… minimum
        val end = minOf(9 + hsLen, b.size)
        if (9 + 34 > end) return null

        var pos = 9
        val helloVersion = u16(b, pos); pos += 2     // client/server hello version
        if ((helloVersion shr 8) != 0x03) return null
        pos += 32                                    // random
        val sidLen = b.getOrNull(pos)?.toInt()?.and(0xff) ?: return null
        pos += 1 + sidLen

        val cipherSuites = mutableListOf<Int>()
        if (isServer) {
            if (pos + 2 > end) return null
            cipherSuites.add(u16(b, pos)); pos += 2  // single selected suite
            pos += 1                                 // selected compression
        } else {
            if (pos + 2 > end) return null
            val csLen = u16(b, pos); pos += 2
            var c = pos
            while (c + 2 <= minOf(pos + csLen, end)) { cipherSuites.add(u16(b, c)); c += 2 }
            pos += csLen
            if (pos >= end) return null
            val compLen = b[pos].toInt() and 0xff; pos += 1 + compLen
        }

        // Extensions (optional)
        var sni = ""
        val alpn = mutableListOf<String>()
        val supportedVersions = mutableListOf<Int>()
        if (pos + 2 <= end) {
            val extLen = u16(b, pos); pos += 2
            val extEnd = minOf(pos + extLen, end)
            while (pos + 4 <= extEnd) {
                val extType = u16(b, pos)
                val extDataLen = u16(b, pos + 2)
                pos += 4
                if (pos + extDataLen > extEnd) break
                when (extType) {
                    0x0000 -> if (extDataLen > 5) {           // server_name
                        val nameLen = u16(b, pos + 3)
                        if (pos + 5 + nameLen <= extEnd) sni = String(b, pos + 5, nameLen, Charsets.US_ASCII)
                    }
                    0x0010 -> if (extDataLen > 2) {           // ALPN
                        var ap = pos + 2
                        val apEnd = pos + extDataLen
                        while (ap < apEnd) {
                            val pLen = b[ap].toInt() and 0xff; ap++
                            if (ap + pLen <= apEnd) alpn.add(String(b, ap, pLen, Charsets.US_ASCII))
                            ap += pLen
                        }
                    }
                    0x002b -> {                               // supported_versions
                        if (!isServer && extDataLen >= 1) {
                            val listLen = b[pos].toInt() and 0xff
                            var vp = pos + 1
                            while (vp + 2 <= pos + 1 + listLen && vp + 2 <= extEnd) { supportedVersions.add(u16(b, vp)); vp += 2 }
                        } else if (isServer && extDataLen >= 2) {
                            supportedVersions.add(u16(b, pos))
                        }
                    }
                }
                pos += extDataLen
            }
        }

        return Parsed(isServer, recordVersion, helloVersion, sni, alpn, cipherSuites, supportedVersions)
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    private companion object {
        val VERSIONS = mapOf(
            0x0300 to "SSL 3.0", 0x0301 to "TLS 1.0", 0x0302 to "TLS 1.1",
            0x0303 to "TLS 1.2", 0x0304 to "TLS 1.3",
        )
        val CIPHERS = mapOf(
            0x1301 to "TLS_AES_128_GCM_SHA256", 0x1302 to "TLS_AES_256_GCM_SHA384",
            0x1303 to "TLS_CHACHA20_POLY1305_SHA256",
            0xC02B to "ECDHE_ECDSA_AES128_GCM_SHA256", 0xC02C to "ECDHE_ECDSA_AES256_GCM_SHA384",
            0xC02F to "ECDHE_RSA_AES128_GCM_SHA256", 0xC030 to "ECDHE_RSA_AES256_GCM_SHA384",
            0xCCA8 to "ECDHE_RSA_CHACHA20_POLY1305", 0xCCA9 to "ECDHE_ECDSA_CHACHA20_POLY1305",
            0x009C to "RSA_AES128_GCM_SHA256", 0x009D to "RSA_AES256_GCM_SHA384",
            0x002F to "RSA_AES128_CBC_SHA", 0x0035 to "RSA_AES256_CBC_SHA", 0x000A to "RSA_3DES_EDE_CBC_SHA",
        )
    }

    private fun versionName(v: Int) = VERSIONS[v] ?: "0x%04x".format(v)
    private fun cipherName(v: Int) = CIPHERS[v] ?: "0x%04x".format(v)
}
