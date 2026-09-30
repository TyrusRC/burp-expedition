package expedition.matchreplace

import expedition.dissector.DissectorRegistry
import expedition.registry.Direction
import expedition.registry.ProxyMessage
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

class MatchReplaceEngine(private val dissectorRegistry: DissectorRegistry? = null) {
    // CopyOnWriteArrayList: rules are mutated from the Swing EDT (Match & Replace panel)
    // while apply() iterates them from Netty worker threads. Copy-on-write gives each
    // apply() a stable snapshot without locking and never throws ConcurrentModificationException.
    private val rules = CopyOnWriteArrayList<MatchReplaceRule>()

    fun addRule(rule: MatchReplaceRule) {
        rules.add(rule)
    }

    fun removeRule(id: Long) {
        rules.removeAll { it.id == id }
    }

    fun rules(): List<MatchReplaceRule> = rules.toList()

    fun apply(input: ByteArray): ByteArray {
        var current = input
        // Raw-byte rules first.
        for (rule in rules.filter { it.enabled && !it.decoded }) {
            current = applyRule(rule, current)
        }
        // Decoded rules: rewrite the dissector's text view, then re-encode (fixes framing).
        val decodedRules = rules.filter { it.enabled && it.decoded }
        if (decodedRules.isNotEmpty() && dissectorRegistry != null) {
            val message = ProxyMessage(0, 0, Direction.CLIENT_TO_UPSTREAM, Instant.now(), current)
            val dissector = dissectorRegistry.dissectorFor(message)
            var text = dissector.render(message)
            for (rule in decodedRules) {
                text = when (rule.matchType) {
                    MatchType.LITERAL_STRING -> text.replace(rule.matchValue, rule.replaceValue)
                    MatchType.REGEX -> text.replace(Regex(rule.matchValue), rule.replaceValue)
                    MatchType.LITERAL_BYTES -> text // hex-byte matching is meaningless on decoded text
                }
            }
            current = dissector.parseEdit(text, message)
        }
        return current
    }

    private fun applyRule(rule: MatchReplaceRule, input: ByteArray): ByteArray = when (rule.matchType) {
        MatchType.LITERAL_STRING ->
            String(input, Charsets.ISO_8859_1)
                .replace(rule.matchValue, rule.replaceValue)
                .toByteArray(Charsets.ISO_8859_1)
        MatchType.REGEX ->
            String(input, Charsets.ISO_8859_1)
                .replace(Regex(rule.matchValue), rule.replaceValue)
                .toByteArray(Charsets.ISO_8859_1)
        MatchType.LITERAL_BYTES ->
            replaceBytes(input, hexToBytes(rule.matchValue), hexToBytes(rule.replaceValue))
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        return ByteArray(clean.length / 2) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun replaceBytes(input: ByteArray, match: ByteArray, replacement: ByteArray): ByteArray {
        if (match.isEmpty()) return input
        val output = mutableListOf<Byte>()
        var i = 0
        while (i < input.size) {
            val matches = i + match.size <= input.size && (0 until match.size).all { input[i + it] == match[it] }
            if (matches) {
                output.addAll(replacement.toList())
                i += match.size
            } else {
                output.add(input[i])
                i += 1
            }
        }
        return output.toByteArray()
    }
}
