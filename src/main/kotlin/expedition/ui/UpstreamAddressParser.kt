package expedition.ui

object UpstreamAddressParser {
    fun parse(address: String): Pair<String, Int> {
        val idx = address.lastIndexOf(':')
        require(idx > 0) { "Invalid upstream address: $address" }
        val host = address.substring(0, idx)
        val port = address.substring(idx + 1).toIntOrNull()
            ?: error("Invalid port in address: $address")
        return host to port
    }
}
