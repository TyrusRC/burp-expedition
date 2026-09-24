package expedition.dissector

import expedition.registry.ProxyMessage

class DissectorRegistry(private val defaultDissector: Dissector = HexStringDissector()) {
    private val dissectors = mutableListOf<Dissector>()

    fun register(dissector: Dissector) {
        dissectors.add(0, dissector)
    }

    fun dissectorFor(message: ProxyMessage): Dissector =
        dissectors.firstOrNull { it.supports(message) } ?: defaultDissector
}
