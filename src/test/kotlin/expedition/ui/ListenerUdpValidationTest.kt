package expedition.ui

import expedition.engine.TlsMode
import expedition.registry.Protocol
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ListenerUdpValidationTest {

    private fun validate(protocol: Protocol, upstreamProxy: String = "", clientCertPath: String = "") =
        ListenerFormValidation.validate(
            name = "u", protocol = protocol, bindHost = "127.0.0.1", bindPort = "5353",
            upstreamHost = "10.0.0.1", upstreamPort = "53", tlsMode = TlsMode.NONE,
            existingNames = emptySet(), upstreamProxy = upstreamProxy, clientCertPath = clientCertPath,
        )

    @Test
    fun `udp rejects an upstream proxy`() {
        val r = validate(Protocol.UDP, upstreamProxy = "10.0.0.2:3128")
        assertTrue(r.isFailure)
        assertTrue(r.exceptionOrNull()!!.message!!.contains("UDP"))
    }

    @Test
    fun `udp rejects a client certificate`() {
        val r = validate(Protocol.UDP, clientCertPath = "/tmp/does-not-matter.p12")
        assertTrue(r.isFailure)
        assertTrue(r.exceptionOrNull()!!.message!!.contains("UDP"))
    }

    @Test
    fun `tcp still accepts an upstream proxy`() {
        assertTrue(validate(Protocol.TCP, upstreamProxy = "10.0.0.2:3128").isSuccess)
    }

    @Test
    fun `udp without proxy or client cert is accepted`() {
        assertTrue(validate(Protocol.UDP).isSuccess)
    }
}
