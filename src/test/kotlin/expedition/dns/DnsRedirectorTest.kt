package expedition.dns

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DnsRedirectorTest {

    /** Build a DNS query for [name] of [qtype] (A=1, AAAA=28), id 0x1234, RD set. */
    private fun query(name: String, qtype: Int): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        u16(0x1234); u16(0x0100); u16(1); u16(0); u16(0); u16(0) // header: id, flags(RD), qd=1
        for (label in name.split(".")) { out.add(label.length.toByte()); out.addAll(label.toByteArray(Charsets.US_ASCII).toList()) }
        out.add(0)
        u16(qtype); u16(1) // QTYPE, QCLASS=IN
        return out.toByteArray()
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    @Test fun `answers a matching name with an A record to the configured IP`() {
        val r = DnsRedirector(listOf(DnsRedirector.Rule("test.local", "10.0.0.5")))
        val resp = r.respond(query("test.local", 1))!!
        assertEquals(0x1234, u16(resp, 0), "echoes query id")
        assertEquals(1, (u16(resp, 2) ushr 15) and 1, "QR=1 (response)")
        assertEquals(0, u16(resp, 2) and 0xf, "RCODE=0 NOERROR")
        assertEquals(1, u16(resp, 4), "QDCOUNT=1")
        assertEquals(1, u16(resp, 6), "ANCOUNT=1")
        // answer RDATA is the last 4 bytes: 10.0.0.5
        assertArrayEquals(byteArrayOf(10, 0, 0, 5), resp.copyOfRange(resp.size - 4, resp.size))
        // answer uses a compression pointer back to the question name
        val answerStart = resp.size - 16 // ptr(2)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata(4)
        assertEquals(0xc0, resp[answerStart].toInt() and 0xff)
        assertEquals(0x0c, resp[answerStart + 1].toInt() and 0xff)
    }

    @Test fun `wildcard rule matches subdomains`() {
        val r = DnsRedirector(listOf(DnsRedirector.Rule("*.example.com", "1.2.3.4")))
        val resp = r.respond(query("api.example.com", 1))!!
        assertEquals(1, u16(resp, 6))
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), resp.copyOfRange(resp.size - 4, resp.size))
    }

    @Test fun `unmatched name with no default returns NXDOMAIN`() {
        val r = DnsRedirector(listOf(DnsRedirector.Rule("test.local", "10.0.0.5")))
        val resp = r.respond(query("other.host", 1))!!
        assertEquals(3, u16(resp, 2) and 0xf, "RCODE=3 NXDOMAIN")
        assertEquals(0, u16(resp, 6), "no answers")
    }

    @Test fun `default IP catches unmatched names`() {
        val r = DnsRedirector(emptyList(), defaultIp = "127.0.0.1")
        val resp = r.respond(query("anything.at.all", 1))!!
        assertEquals(1, u16(resp, 6))
        assertArrayEquals(byteArrayOf(127, 0, 0, 1), resp.copyOfRange(resp.size - 4, resp.size))
    }

    @Test fun `answers AAAA when the rule IP is IPv6`() {
        val r = DnsRedirector(listOf(DnsRedirector.Rule("v6.local", "::1")))
        val resp = r.respond(query("v6.local", 28))!!
        assertEquals(1, u16(resp, 6))
        val rdata = resp.copyOfRange(resp.size - 16, resp.size)
        assertEquals(1, rdata[15].toInt(), "::1 last byte")
    }

    @Test fun `A query against an IPv6-only rule yields NOERROR with no answer`() {
        val r = DnsRedirector(listOf(DnsRedirector.Rule("v6.local", "::1")))
        val resp = r.respond(query("v6.local", 1))!! // A query, rule is IPv6
        assertEquals(0, u16(resp, 2) and 0xf, "RCODE=0")
        assertEquals(0, u16(resp, 6), "no A record of that type")
    }

    @Test fun `ignores a packet that is already a response`() {
        val q = query("test.local", 1)
        q[2] = 0x81.toByte() // set QR bit
        assertNull(DnsRedirector(listOf(DnsRedirector.Rule("test.local", "10.0.0.5"))).respond(q))
    }

    @Test fun `ignores malformed input`() {
        assertNull(DnsRedirector(emptyList(), "1.2.3.4").respond(byteArrayOf(0, 1, 2)))
    }

    @Test fun `case-insensitive host matching`() {
        val r = DnsRedirector(listOf(DnsRedirector.Rule("Test.LOCAL", "10.0.0.5")))
        assertTrue(r.respond(query("test.local", 1))!!.let { u16(it, 6) == 1 })
    }
}
