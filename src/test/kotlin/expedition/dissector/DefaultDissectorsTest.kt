package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant

/**
 * Guards the real dissector line-up used by the extension: that each protocol's
 * representative message is routed to the right dissector, and that the least-specific
 * matchers (notably Kafka, which has no magic bytes) don't steal other protocols'
 * traffic. This is the registration-order contract the Burp UI and the decoded
 * match/replace path depend on — untested while it lived inline in ExpeditionExtension.
 */
class DefaultDissectorsTest {

    private val registry = defaultDissectors()
    private fun msg(b: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), b)
    private inline fun <reified T> routesTo(b: ByteArray) =
        assertTrue(registry.dissectorFor(msg(b)) is T,
            "expected ${T::class.simpleName} for ${b.joinToString(" ") { "%02x".format(it) }}, " +
            "got ${registry.dissectorFor(msg(b))::class.simpleName}")

    private fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

    @Test fun `AMQP protocol header routes to the AMQP dissector`() {
        routesTo<AmqpDissector>(byteArrayOf(0x41, 0x4D, 0x51, 0x50, 0x00, 0x00, 0x09, 0x01))
    }

    @Test fun `an LDAP bindRequest routes to the LDAP dissector`() {
        // SEQUENCE { INTEGER messageID=1, [APPLICATION 0] bindRequest {} }
        routesTo<LdapDissector>(byteArrayOf(0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00))
    }

    @Test fun `a Kafka ApiVersions request routes to the Kafka dissector`() {
        val body = u16(18) + u16(3) + byteArrayOf(0, 0, 0, 1) + u16(1) + "x".toByteArray()
        routesTo<KafkaDissector>(byteArrayOf(0, 0, 0, body.size.toByte()) + body)
    }

    @Test fun `an SMB2 NEGOTIATE request routes to the SMB2 dissector`() {
        val b = ByteArray(64)
        b[0] = 0xFE.toByte(); b[1] = 0x53; b[2] = 0x4D; b[3] = 0x42  // magic
        b[4] = 0x40; b[5] = 0x00                                     // StructureSize = 64 (LE)
        routesTo<Smb2Dissector>(b)
    }

    @Test fun `Redis is not stolen by a less-specific binary dissector`() {
        routesTo<RedisDissector>("+PONG\r\n".toByteArray())
    }

    @Test fun `a gRPC length-prefixed protobuf message routes to the gRPC dissector`() {
        val pb = byteArrayOf(0x08, 0x05, 0x12, 0x02, 0x68, 0x69) // protobuf
        routesTo<GrpcDissector>(byteArrayOf(0x00, 0x00, 0x00, 0x00, pb.size.toByte()) + pb)
    }

    @Test fun `a TLS ClientHello still routes to the TLS dissector`() {
        // minimal ClientHello record (handshake, TLS1.0 record, ClientHello, TLS1.2 body)
        val body = byteArrayOf(0x03, 0x03) + ByteArray(32) + byteArrayOf(0x00) + u16(2) + u16(0x1301) +
            byteArrayOf(0x01, 0x00) + u16(0)
        val hs = byteArrayOf(0x01, (body.size shr 16).toByte(), (body.size shr 8).toByte(), body.size.toByte()) + body
        routesTo<TlsDissector>(byteArrayOf(0x16, 0x03, 0x01) + u16(hs.size) + hs)
    }
}
