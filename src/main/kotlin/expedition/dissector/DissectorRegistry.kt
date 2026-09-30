package expedition.dissector

import expedition.registry.ProxyMessage

class DissectorRegistry(private val defaultDissector: Dissector = HexStringDissector()) {
    private val dissectors = mutableListOf<Dissector>()

    fun register(dissector: Dissector) {
        dissectors.add(0, dissector)
    }

    fun dissectorFor(message: ProxyMessage): Dissector =
        // A buggy/throwing supports() (e.g. on crafted bytes) must never crash the caller
        // (History/Intercept render, or the decoded match-replace path) — fall through to the next.
        dissectors.firstOrNull { runCatching { it.supports(message) }.getOrDefault(false) } ?: defaultDissector
}
