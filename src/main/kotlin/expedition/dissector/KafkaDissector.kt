package expedition.dissector

import expedition.registry.ProxyMessage

/**
 * Kafka wire protocol dissector (client REQUEST side).
 *
 * A request on the wire is: size(4 BE int32 = length of the rest) then the request header:
 * apiKey(2 BE int16), apiVersion(2 BE int16), correlationId(4 BE int32), then clientId as a
 * Kafka nullable STRING (2 BE int16 length N, then N bytes UTF-8; N == -1 means null), then body.
 *
 * Kafka has no magic bytes, so supports() combines several consistent structural invariants to
 * stay specific and avoid stealing other protocols' traffic (see [parse]).
 *
 * Security testing value: broker protocol enumeration, clientId/ACL fingerprinting, and spotting
 * unauthenticated producer/consumer traffic.
 */
class KafkaDissector : Dissector {

    companion object {
        private val API_NAMES = mapOf(
            0 to "Produce",
            1 to "Fetch",
            2 to "ListOffsets",
            3 to "Metadata",
            8 to "OffsetCommit",
            9 to "OffsetFetch",
            10 to "FindCoordinator",
            11 to "JoinGroup",
            12 to "Heartbeat",
            14 to "SyncGroup",
            18 to "ApiVersions",
            19 to "CreateTopics",
        )
    }

    override fun supports(message: ProxyMessage): Boolean = parse(message.rawBytes) != null

    override fun render(message: ProxyMessage): String {
        val p = parse(message.rawBytes) ?: return HexStringDissector().render(message)
        val apiName = API_NAMES[p.apiKey] ?: "ApiKey(${p.apiKey})"
        val clientId = p.clientId ?: "(null)"
        return buildString {
            append("Kafka $apiName request  v${p.apiVersion}  correlationId=${p.correlationId}  clientId=$clientId")
            append("\nraw: hex:${message.rawBytes.toHex()}")
        }
    }

    override fun parseEdit(edited: String, original: ProxyMessage): ByteArray {
        val rawLine = edited.split("\n").map { it.trim() }
            .firstOrNull { it.startsWith("raw: hex:") || it.startsWith("hex:") }
            ?: return original.rawBytes
        return hexToBytes(rawLine.substringAfter("hex:"))
    }

    private data class Parsed(
        val apiKey: Int,
        val apiVersion: Int,
        val correlationId: Int,
        val clientId: String?,
    )

    private fun parse(bytes: ByteArray): Parsed? {
        // size(4) + apiKey(2) + apiVersion(2) + correlationId(4) + clientId length(2) = 14 minimum
        if (bytes.size < 14) return null

        val size = i32(bytes, 0)
        if (size != bytes.size - 4) return null // length prefix must match the actual buffer

        val apiKey = u16(bytes, 4)
        if (apiKey !in 0..74) return null

        val apiVersion = u16(bytes, 6)
        if (apiVersion !in 0..20) return null

        val correlationId = i32(bytes, 8)
        if (correlationId < 0) return null

        val clientIdLen = s16(bytes, 12)
        if (clientIdLen < -1) return null
        val clientId: String?
        if (clientIdLen == -1) {
            clientId = null
        } else {
            if (14 + clientIdLen > bytes.size) return null // clientId must fit within the buffer
            clientId = String(bytes, 14, clientIdLen, Charsets.UTF_8)
        }

        return Parsed(apiKey, apiVersion, correlationId, clientId)
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
    private fun s16(b: ByteArray, i: Int) = u16(b, i).toShort().toInt() // signed int16 (-1 == null)
    private fun i32(b: ByteArray, i: Int) =
        ((b[i].toInt() and 0xff) shl 24) or ((b[i + 1].toInt() and 0xff) shl 16) or
        ((b[i + 2].toInt() and 0xff) shl 8) or (b[i + 3].toInt() and 0xff)
}
