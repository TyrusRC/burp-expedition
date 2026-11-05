package expedition.dns

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class DnsServerTest {

    private fun query(name: String, qtype: Int): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        u16(0x1234); u16(0x0100); u16(1); u16(0); u16(0); u16(0)
        for (label in name.split(".")) { out.add(label.length.toByte()); out.addAll(label.toByteArray(Charsets.US_ASCII).toList()) }
        out.add(0); u16(qtype); u16(1)
        return out.toByteArray()
    }

    @Test fun `serves a redirected A answer over UDP and stops cleanly`() {
        val redirector = DnsRedirector(listOf(DnsRedirector.Rule("*", "10.9.8.7")))
        val server = DnsServer("127.0.0.1", 0, redirector)
        server.start()
        try {
            val client = DatagramSocket()
            client.soTimeout = 3000
            val q = query("victim.app", 1)
            client.send(DatagramPacket(q, q.size, InetAddress.getByName("127.0.0.1"), server.boundPort()))
            val buf = ByteArray(4096)
            val resp = DatagramPacket(buf, buf.size)
            client.receive(resp)
            client.close()
            val r = buf.copyOfRange(0, resp.length)
            // id echoed, one answer, RDATA = 10.9.8.7
            assertEquals(0x1234, ((r[0].toInt() and 0xff) shl 8) or (r[1].toInt() and 0xff))
            assertArrayEquals(byteArrayOf(10, 9, 8, 7), r.copyOfRange(r.size - 4, r.size))
        } finally {
            server.stop()
        }
        // after stop, the port is free again (re-bind must succeed)
        val reuse = DatagramSocket(server.boundPort(), InetAddress.getByName("127.0.0.1"))
        assertFalse(reuse.isClosed)
        reuse.close()
    }
}
