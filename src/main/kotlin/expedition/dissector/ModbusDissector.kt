package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * Modbus/TCP dissector. Decodes the MBAP header (transaction id, unit id) and the function
 * code into a readable summary; the PDU data is shown as raw hex and edits round-trip via
 * the `raw: hex:` line.
 *
 * NOTE: summary + raw body (register addresses/values not individually decoded in v1).
 */
class ModbusDissector : Dissector {

    private val functions = mapOf(
        1 to "ReadCoils", 2 to "ReadDiscreteInputs", 3 to "ReadHoldingRegisters", 4 to "ReadInputRegisters",
        5 to "WriteSingleCoil", 6 to "WriteSingleRegister", 15 to "WriteMultipleCoils",
        16 to "WriteMultipleRegisters", 23 to "ReadWriteMultipleRegisters"
    )

    private data class Frame(val txn: Int, val unit: Int, val function: Int, val total: Int)

    override fun supports(message: ProxyMessage): Boolean {
        val f = parse(message.rawBytes) ?: return false
        return f.total == message.rawBytes.size
    }

    override fun render(message: ProxyMessage): String {
        val f = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val fn = functions[f.function] ?: "func${f.function}"
        return "Modbus txn=${f.txn} unit=${f.unit} func=$fn\nraw: hex:${message.rawBytes.toHex()}"
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val rawLine = edited.split("\n").map { it.trim() }
            .firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private fun parse(bytes: ByteArray): Frame? {
        if (bytes.size < 8) return null
        fun be(i: Int) = ((bytes[i].toInt() and 0xff) shl 8) or (bytes[i + 1].toInt() and 0xff)
        val txn = be(0)
        val proto = be(2)
        val length = be(4)
        if (proto != 0) return null
        val unit = bytes[6].toInt() and 0xff
        val function = bytes[7].toInt() and 0xff
        // length counts the unit id + PDU; total = 6 (txn+proto+len fields) + length.
        val total = 6 + length
        if (length < 2 || total > bytes.size) return null
        return Frame(txn, unit, function, total)
    }


}
