package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.time.Instant

private fun msg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

/**
 * Build a Kafka client request on the wire: size prefix (int32 BE = length of the rest) then the
 * request header (apiKey, apiVersion, correlationId, clientId as a nullable string) then the body.
 * clientId == null is encoded as a length of -1.
 */
private fun kafkaRequest(
    apiKey: Int,
    apiVersion: Int,
    correlationId: Int,
    clientId: String?,
    body: ByteArray = ByteArray(0),
): ByteArray {
    val clientIdBytes = clientId?.toByteArray(Charsets.UTF_8)
    val clientIdLen = clientIdBytes?.size ?: -1
    val restSize = 2 + 2 + 4 + 2 + (clientIdBytes?.size ?: 0) + body.size
    val buf = ByteBuffer.allocate(4 + restSize)
    buf.putInt(restSize)
    buf.putShort(apiKey.toShort())
    buf.putShort(apiVersion.toShort())
    buf.putInt(correlationId)
    buf.putShort(clientIdLen.toShort())
    if (clientIdBytes != null) buf.put(clientIdBytes)
    buf.put(body)
    return buf.array()
}

class KafkaDissectorTest {

    private val d = KafkaDissector()

    private val apiVersions = kafkaRequest(18, 3, 1, "adminclient")
    private val metadataNullClient = kafkaRequest(3, 9, 42, null)

    @Test
    fun `supports an ApiVersions request`() {
        assertTrue(d.supports(msg(apiVersions)))
    }

    @Test
    fun `supports a Metadata request with null clientId`() {
        assertTrue(d.supports(msg(metadataNullClient)))
    }

    @Test
    fun `rejects random bytes`() {
        assertFalse(d.supports(msg(ByteArray(32) { it.toByte() })))
    }

    @Test
    fun `rejects empty`() {
        assertFalse(d.supports(msg(ByteArray(0))))
    }

    @Test
    fun `rejects a redis PONG`() {
        assertFalse(d.supports(msg("+PONG\r\n".toByteArray())))
    }

    @Test
    fun `rejects a buffer whose size prefix does not match`() {
        val corrupted = apiVersions.copyOf()
        corrupted[3] = (corrupted[3] + 1).toByte() // size prefix now one too large
        assertFalse(d.supports(msg(corrupted)))
    }

    @Test
    fun `render summarizes the ApiVersions request`() {
        val out = d.render(msg(apiVersions))
        assertTrue(out.contains("Kafka"), out)
        assertTrue(out.contains("ApiVersions"), out)
        assertTrue(out.contains("correlationId=1"), out)
        assertTrue(out.contains("adminclient"), out)
    }

    @Test
    fun `parseEdit round-trips the raw hex line back to the original bytes`() {
        val m = msg(apiVersions)
        assertArrayEquals(apiVersions, d.parseEdit(d.render(m), m))
    }
}
