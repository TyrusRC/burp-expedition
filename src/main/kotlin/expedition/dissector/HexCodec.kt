package expedition.dissector

/**
 * Shared hex helpers for the dissectors: `render()` emits hex for raw/binary fields, and
 * `parseEdit()` reads a `hex:` line back to bytes. Kept in one place so every dissector agrees
 * on the encoding (whitespace-tolerant on decode).
 */
internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

internal fun hexToBytes(hex: String): ByteArray {
    val clean = hex.filterNot { it.isWhitespace() }
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
