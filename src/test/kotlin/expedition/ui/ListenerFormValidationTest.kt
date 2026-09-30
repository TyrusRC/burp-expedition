package expedition.ui

import expedition.engine.TlsMode
import expedition.registry.Protocol
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ListenerFormValidationTest {

    @Test
    fun `accepts a well-formed listener form`() {
        val result = ListenerFormValidation.validate(
            "l1", Protocol.TCP, "127.0.0.1", "9000", "example.test", "443", TlsMode.NONE, emptySet()
        )
        assertTrue(result.isSuccess)
        assertEquals("l1", result.getOrThrow().name)
        assertEquals(9000, result.getOrThrow().bindPort)
    }

    @Test
    fun `rejects a blank name`() {
        val result = ListenerFormValidation.validate("", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.NONE, emptySet())
        assertTrue(result.isFailure)
    }

    @Test
    fun `rejects a name that is already running`() {
        val result = ListenerFormValidation.validate("dup", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.NONE, setOf("dup"))
        assertTrue(result.isFailure)
    }

    @Test
    fun `rejects an out-of-range bind port`() {
        val result = ListenerFormValidation.validate("l1", Protocol.TCP, "127.0.0.1", "70000", "h", "443", TlsMode.NONE, emptySet())
        assertTrue(result.isFailure)
    }

    @Test
    fun `rejects a non-numeric upstream port`() {
        val result = ListenerFormValidation.validate("l1", Protocol.TCP, "127.0.0.1", "9000", "h", "abc", TlsMode.NONE, emptySet())
        assertTrue(result.isFailure)
    }

    @Test
    fun `rejects a blank upstream host`() {
        val result = ListenerFormValidation.validate("l1", Protocol.TCP, "127.0.0.1", "9000", "", "443", TlsMode.NONE, emptySet())
        assertTrue(result.isFailure)
    }

    @Test
    fun `rejects a TLS MITM listener when no CA keystore has been configured`() {
        val result = ListenerFormValidation.validate(
            "l1", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.MITM, emptySet(),
            certificateProviderConfigured = false
        )
        assertTrue(result.isFailure)
    }

    @Test
    fun `accepts a TLS MITM listener once a CA keystore has been configured`() {
        val result = ListenerFormValidation.validate(
            "l1", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.MITM, emptySet(),
            certificateProviderConfigured = true
        )
        assertTrue(result.isSuccess)
    }

    @Test
    fun `parses an upstream proxy host and port`() {
        val result = ListenerFormValidation.validate(
            "l1", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.NONE, emptySet(),
            upstreamProxy = "127.0.0.1:1080"
        )
        assertTrue(result.isSuccess)
        val proxy = result.getOrThrow().upstreamProxy!!
        assertEquals("127.0.0.1", proxy.host)
        assertEquals(1080, proxy.port)
    }

    @Test
    fun `rejects a malformed upstream proxy`() {
        val result = ListenerFormValidation.validate(
            "l1", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.NONE, emptySet(),
            upstreamProxy = "nope"
        )
        assertTrue(result.isFailure)
    }

    @Test
    fun `sets upstream client auth from a keystore path`() {
        val result = ListenerFormValidation.validate(
            "l1", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.NONE, emptySet(),
            clientCertPath = "/tmp/client.p12", clientCertPassword = "pw".toCharArray()
        )
        assertTrue(result.isSuccess)
        assertNotNull(result.getOrThrow().upstreamClientAuth)
    }

    @Test
    fun `requires a CA keystore for STARTTLS too`() {
        val result = ListenerFormValidation.validate(
            "l1", Protocol.TCP, "127.0.0.1", "9000", "h", "443", TlsMode.STARTTLS, emptySet(),
            certificateProviderConfigured = false
        )
        assertTrue(result.isFailure)
    }
}
