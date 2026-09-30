package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun mqttMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class MqttDissectorTest {

    private val d = MqttDissector()

    // PUBLISH, QoS 0, topic "a/b", payload "hi"
    private val publish = byteArrayOf(0x30, 0x07, 0x00, 0x03) + "a/b".toByteArray() + "hi".toByteArray()

    @Test
    fun `renders a PUBLISH packet with topic and payload`() {
        val out = d.render(mqttMsg(publish))
        assertTrue(out.contains("MQTT PUBLISH"), out)
        assertTrue(out.contains("topic: a/b"), out)
        assertTrue(out.contains("payload: str:hi"), out)
    }

    @Test
    fun `round-trips a PUBLISH packet through render and parseEdit`() {
        val original = mqttMsg(publish)
        assertArrayEquals(publish, d.parseEdit(d.render(original), original))
    }

    @Test
    fun `renders and round-trips a non-PUBLISH packet via raw hex`() {
        val pingreq = byteArrayOf(0xC0.toByte(), 0x00) // PINGREQ
        val original = mqttMsg(pingreq)
        val rendered = d.render(original)
        assertTrue(rendered.contains("MQTT PINGREQ"), rendered)
        assertArrayEquals(pingreq, d.parseEdit(rendered, original))
    }

    @Test
    fun `supports a valid single MQTT packet and rejects non-MQTT`() {
        assertTrue(d.supports(mqttMsg(publish)))
        assertTrue(d.supports(mqttMsg(byteArrayOf(0xC0.toByte(), 0x00))))
        // remaining length claims 5 but only 1 byte present
        assertFalse(d.supports(mqttMsg(byteArrayOf(0x30, 0x05, 0x41))))
        // packet type 0 is reserved/invalid
        assertFalse(d.supports(mqttMsg(byteArrayOf(0x00, 0x00))))
        assertFalse(d.supports(mqttMsg(byteArrayOf())))
    }
}
