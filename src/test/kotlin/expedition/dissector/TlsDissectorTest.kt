package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.time.Instant

private fun tlsMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

private fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

/** Build a minimal but well-formed TLS ClientHello record with the given SNI/ALPN/suites. */
private fun clientHello(
    sni: String? = "example.com",
    alpn: List<String> = listOf("h2", "http/1.1"),
    suites: List<Int> = listOf(0x1301, 0xC02F),
): ByteArray {
    val exts = ByteArrayOutputStream()
    if (sni != null) {
        val host = sni.toByteArray(Charsets.US_ASCII)
        val entry = byteArrayOf(0x00) + u16(host.size) + host     // name_type=host_name(0)
        val list = u16(entry.size) + entry                        // server_name_list
        exts.write(u16(0x0000)); exts.write(u16(list.size)); exts.write(list)
    }
    run {
        val protos = ByteArrayOutputStream()
        alpn.forEach { protos.write(it.length); protos.write(it.toByteArray(Charsets.US_ASCII)) }
        val list = u16(protos.size()) + protos.toByteArray()
        exts.write(u16(0x0010)); exts.write(u16(list.size)); exts.write(list)
    }
    val extsBlock = u16(exts.size()) + exts.toByteArray()

    val suiteBytes = ByteArrayOutputStream().apply { suites.forEach { write(u16(it)) } }.toByteArray()
    val body = byteArrayOf(0x03, 0x03) + ByteArray(32) + byteArrayOf(0x00) +   // version, random, sid_len=0
        u16(suiteBytes.size) + suiteBytes + byteArrayOf(0x01, 0x00) + extsBlock // suites, comp, exts
    val hs = byteArrayOf(0x01) + byteArrayOf((body.size shr 16).toByte(), (body.size shr 8).toByte(), body.size.toByte()) + body
    return byteArrayOf(0x16, 0x03, 0x01) + u16(hs.size) + hs
}

private fun ByteArrayOutputStream.write(b: ByteArray) = write(b, 0, b.size)

class TlsDissectorTest {

    private val d = TlsDissector()

    @Test
    fun `supports a TLS ClientHello record`() {
        assertTrue(d.supports(tlsMsg(clientHello())))
    }

    @Test
    fun `rejects non-TLS data`() {
        assertFalse(d.supports(tlsMsg(byteArrayOf(1, 2, 3, 4, 5, 6))))
        assertFalse(d.supports(tlsMsg("+PONG\r\n".toByteArray())))
        assertFalse(d.supports(tlsMsg(byteArrayOf())))
    }

    @Test
    fun `renders the SNI, ALPN and a cipher suite`() {
        val out = d.render(tlsMsg(clientHello(sni = "target.internal", alpn = listOf("h2"))))
        assertTrue(out.contains("ClientHello"), out)
        assertTrue(out.contains("target.internal"), out)
        assertTrue(out.contains("h2"), out)
        assertTrue(out.contains("TLS_AES_128_GCM_SHA256"), out) // 0x1301 named
    }

    @Test
    fun `round-trips the raw bytes through render and parseEdit`() {
        val bytes = clientHello()
        val msg = tlsMsg(bytes)
        assertArrayEquals(bytes, d.parseEdit(d.render(msg), msg))
    }
}
