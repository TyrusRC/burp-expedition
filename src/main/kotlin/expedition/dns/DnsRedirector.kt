package expedition.dns

import java.net.InetAddress

/**
 * Pure DNS redirect logic (RFC 1035): given a query packet, build a response that points a
 * target host at an attacker-chosen IP — the standard way to pull a thick client's or mobile
 * app's non-HTTP traffic into the proxy (cf. NoPE Proxy's configurable DNS server). The actual
 * UDP socket lives in [DnsServer]; keeping the packet logic here makes it testable without I/O.
 *
 * Rules match the query name (case-insensitive) in order; the first match wins. A rule host of
 * `*` matches everything and `*.suffix` matches `suffix` and any subdomain of it. [defaultIp] is
 * the catch-all for names no rule matches; with no default, an unmatched name gets NXDOMAIN.
 *
 * Only A (IPv4) and AAAA (IPv6) are answered. A query whose type doesn't match the resolved IP's
 * family returns NOERROR with no answer (the correct "no record of that type" response), never a
 * lie of the wrong family.
 *
 * NOTE: no upstream forwarding — an unmatched name with no default is NXDOMAIN, not resolved for
 * real. Pass-through to a real resolver is the obvious next step (upgrade path: inject a resolver).
 */
class DnsRedirector(
    private val rules: List<Rule>,
    private val defaultIp: String? = null,
    private val ttlSeconds: Int = 60,
) {
    data class Rule(val hostPattern: String, val ip: String)

    private data class Query(val id: Int, val flags: Int, val name: String, val qtype: Int, val questionBytes: ByteArray)

    /** Builds a response for [query], or null if the packet isn't a standard query we should answer. */
    fun respond(query: ByteArray): ByteArray? {
        val q = parse(query) ?: return null
        val ip = resolve(q.name.lowercase()) ?: return build(q, rcode = 3, rdata = null, answerType = q.qtype)
        val ipBytes = ipToBytes(ip) ?: return build(q, rcode = 2, rdata = null, answerType = q.qtype) // SERVFAIL on bad config
        val family = if (ipBytes.size == 4) 1 else 28 // A or AAAA
        // Answer only when the query type matches the IP family; otherwise NOERROR / no answer.
        return if (q.qtype == family) build(q, rcode = 0, rdata = ipBytes, answerType = family)
        else build(q, rcode = 0, rdata = null, answerType = q.qtype)
    }

    private fun resolve(host: String): String? {
        for (r in rules) if (matches(r.hostPattern.lowercase(), host)) return r.ip
        return defaultIp
    }

    private fun matches(pattern: String, host: String): Boolean = when {
        pattern == "*" -> true
        pattern.startsWith("*.") -> {
            val suffix = pattern.substring(2)
            host == suffix || host.endsWith(".$suffix")
        }
        else -> pattern == host
    }

    private fun ipToBytes(ip: String): ByteArray? = runCatching {
        // Literal IPs resolve offline; reject a hostname (would require a real lookup).
        if (ip.none { it == '.' || it == ':' }) return null
        InetAddress.getByName(ip).address
    }.getOrNull()

    private fun parse(bytes: ByteArray): Query? {
        if (bytes.size < 12) return null
        fun u16(i: Int) = ((bytes[i].toInt() and 0xff) shl 8) or (bytes[i + 1].toInt() and 0xff)
        val id = u16(0); val flags = u16(2); val qd = u16(4)
        if ((flags shr 15) and 1 != 0) return null       // already a response
        if ((flags shr 11) and 0xf != 0) return null      // not a standard query (opcode != 0)
        if (qd < 1) return null
        var pos = 12
        val labels = ArrayList<String>()
        while (true) {
            if (pos >= bytes.size) return null
            val len = bytes[pos].toInt() and 0xff
            if (len == 0) { pos++; break }
            if (len and 0xc0 != 0) return null            // compression in a question — bail
            if (pos + 1 + len > bytes.size) return null
            labels.add(String(bytes, pos + 1, len, Charsets.US_ASCII))
            pos += 1 + len
        }
        if (pos + 4 > bytes.size) return null
        val qtype = u16(pos); pos += 4                     // skip QTYPE + QCLASS
        return Query(id, flags, labels.joinToString("."), qtype, bytes.copyOfRange(12, pos))
    }

    private fun build(q: Query, rcode: Int, rdata: ByteArray?, answerType: Int): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        val answers = if (rdata != null) 1 else 0
        // QR=1, RA=1, copy RD from the query; opcode 0.
        val flags = 0x8000 or 0x0080 or (q.flags and 0x0100) or (rcode and 0xf)
        u16(q.id); u16(flags); u16(1); u16(answers); u16(0); u16(0) // header
        out.addAll(q.questionBytes.toList())                        // echo the question
        if (rdata != null) {
            out.add(0xc0.toByte()); out.add(0x0c.toByte())          // name: pointer to offset 12
            u16(answerType); u16(1)                                  // TYPE, CLASS=IN
            // TTL (32-bit)
            out.add((ttlSeconds ushr 24).toByte()); out.add((ttlSeconds ushr 16).toByte())
            out.add((ttlSeconds ushr 8).toByte()); out.add(ttlSeconds.toByte())
            u16(rdata.size)                                          // RDLENGTH
            out.addAll(rdata.toList())                               // RDATA
        }
        return out.toByteArray()
    }
}
