package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun mongoMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class MongoDissectorTest {

    private val d = MongoDissector()

    // header: len=21(LE), reqId=1, respTo=0, opCode=2013 (OP_MSG); + 5 body bytes
    private val opMsg = byteArrayOf(0x15, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xDD.toByte(), 0x07, 0, 0, 0, 0, 0, 0, 0)

    @Test
    fun `renders the Mongo header with opcode and request id`() {
        val out = d.render(mongoMsg(opMsg))
        assertTrue(out.contains("Mongo OP_MSG"), out)
        assertTrue(out.contains("reqId=1"), out)
    }

    @Test
    fun `round-trips via raw hex`() {
        assertArrayEquals(opMsg, d.parseEdit(d.render(mongoMsg(opMsg)), mongoMsg(opMsg)))
    }

    @Test
    fun `supports a valid Mongo message and rejects non-Mongo`() {
        assertTrue(d.supports(mongoMsg(opMsg)))
        assertFalse(d.supports(mongoMsg(byteArrayOf())))
        assertFalse(d.supports(mongoMsg(byteArrayOf(1, 2, 3, 4))))
        // messageLength doesn't match buffer size
        assertFalse(d.supports(mongoMsg(byteArrayOf(0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xDD.toByte(), 0x07, 0, 0))))
    }
}
