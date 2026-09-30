package expedition.engine

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class StartTlsDetectorTest {

    private val pgSslRequest = byteArrayOf(0x00, 0x00, 0x00, 0x08, 0x04, 0xd2.toByte(), 0x16, 0x2f)

    @Test
    fun `SMTP STARTTLS then 220 go-ahead triggers upgrade`() {
        val d = StartTlsDetector()
        assertFalse(d.onClientData("STARTTLS\r\n".toByteArray()))
        assertTrue(d.onUpstreamData("220 2.0.0 Ready to start TLS\r\n".toByteArray()))
    }

    @Test
    fun `POP3 STLS then plus-OK triggers upgrade`() {
        val d = StartTlsDetector()
        assertFalse(d.onClientData("STLS\r\n".toByteArray()))
        assertTrue(d.onUpstreamData("+OK Begin TLS negotiation\r\n".toByteArray()))
    }

    @Test
    fun `IMAP tagged STARTTLS then tagged OK triggers upgrade`() {
        val d = StartTlsDetector()
        assertFalse(d.onClientData("a001 STARTTLS\r\n".toByteArray()))
        assertTrue(d.onUpstreamData("a001 OK Begin TLS negotiation now\r\n".toByteArray()))
    }

    @Test
    fun `Postgres SSLRequest then S triggers upgrade`() {
        val d = StartTlsDetector()
        assertFalse(d.onClientData(pgSslRequest))
        assertTrue(d.onUpstreamData(byteArrayOf('S'.code.toByte())))
    }

    @Test
    fun `Postgres SSLRequest declined with N does not upgrade`() {
        val d = StartTlsDetector()
        assertFalse(d.onClientData(pgSslRequest))
        assertFalse(d.onUpstreamData(byteArrayOf('N'.code.toByte())))
    }

    @Test
    fun `server go-ahead without a prior client request does not upgrade`() {
        val d = StartTlsDetector()
        assertFalse(d.onUpstreamData("220 mail.example.com ESMTP\r\n".toByteArray()))
    }

    @Test
    fun `SMTP failure response after STARTTLS does not upgrade`() {
        val d = StartTlsDetector()
        assertFalse(d.onClientData("STARTTLS\r\n".toByteArray()))
        assertFalse(d.onUpstreamData("454 4.7.0 TLS not available\r\n".toByteArray()))
    }
}
