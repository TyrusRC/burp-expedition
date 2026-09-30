package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun mbMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class ModbusDissectorTest {

    private val d = ModbusDissector()

    // MBAP txn=1 proto=0 len=6 unit=1 ; PDU func=3 (Read Holding Registers) addr=0 qty=10
    private val readHolding = byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A)

    @Test
    fun `renders the function and unit`() {
        val out = d.render(mbMsg(readHolding))
        assertTrue(out.contains("Modbus"), out)
        assertTrue(out.contains("ReadHoldingRegisters"), out)
        assertTrue(out.contains("unit=1"), out)
    }

    @Test
    fun `round-trips via raw hex`() {
        assertArrayEquals(readHolding, d.parseEdit(d.render(mbMsg(readHolding)), mbMsg(readHolding)))
    }

    @Test
    fun `supports valid Modbus TCP and rejects non-Modbus`() {
        assertTrue(d.supports(mbMsg(readHolding)))
        assertFalse(d.supports(mbMsg(byteArrayOf())))
        // protocol id non-zero
        assertFalse(d.supports(mbMsg(byteArrayOf(0x00, 0x01, 0x00, 0x09, 0x00, 0x06, 0x01, 0x03, 0, 0, 0, 10))))
        // length field doesn't match buffer
        assertFalse(d.supports(mbMsg(byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x01, 0x03))))
    }
}
