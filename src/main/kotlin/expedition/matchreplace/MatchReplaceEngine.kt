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
            val before = dissector.render(message)
            var text = before
            for (rule in decodedRules) {
                text = when (rule.matchType) {
                    MatchType.LITERAL_STRING -> text.replace(rule.matchValue, rule.replaceValue)
                    MatchType.REGEX -> safeRegexReplace(rule.regex!!, text, rule.replaceValue)
                    MatchType.LITERAL_BYTES -> text // hex-byte matching is meaningless on decoded text
                }
            }
            // Only re-encode when a rule actually changed the decoded view — otherwise a
            // non-bit-exact round-trip would corrupt traffic no rule even matched.
            if (text != before) current = dissector.parseEdit(text, message)
        }
        return current
    }

    private fun applyRule(rule: MatchReplaceRule, input: ByteArray): ByteArray = when (rule.matchType) {
        MatchType.LITERAL_STRING ->
            String(input, Charsets.ISO_8859_1)
                .replace(rule.matchValue, rule.replaceValue)
                .toByteArray(Charsets.ISO_8859_1)
        MatchType.REGEX ->
            safeRegexReplace(rule.regex!!, String(input, Charsets.ISO_8859_1), rule.replaceValue)
                .toByteArray(Charsets.ISO_8859_1)
        MatchType.LITERAL_BYTES ->
            replaceBytes(input, hexToBytes(rule.matchValue), hexToBytes(rule.replaceValue))
    }

    /**
     * Run [regex].replace under a hard cap on character accesses, so a catastrophic-
     * backtracking (ReDoS) pattern against attacker-influenced bytes cannot pin a Netty
     * worker thread. If the cap is hit — or the replace fails for any reason — the input
     * is returned UNCHANGED (fail-safe): a mis-applied rule must never corrupt or stall
     * the proxied stream. Legitimate work is linear in the input, so the cap is only ever
     * reached by pathological backtracking.
     */
    private fun safeRegexReplace(regex: Regex, input: String, replacement: String): String =
        try {
            regex.replace(BudgetedCharSequence(input, charAccessBudget(input.length)), replacement)
        } catch (e: RegexBudgetExceededException) {
            input
        } catch (e: Exception) {
            input
        }

    private fun charAccessBudget(len: Int): Long =
        // Generous headroom for honest matches (linear in length) while still cutting off
        // exponential backtracking long before it becomes a stall.
        maxOf(MIN_CHAR_BUDGET, len.toLong() * PER_CHAR_BUDGET)

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        return ByteArray(clean.length / 2) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private companion object {
        // 5M minimum covers small messages matched by heavy-but-honest patterns; 4K per input
        // char keeps the cap proportional for large payloads. Exponential backtracking blows
        // past these by orders of magnitude, so the cap only ever trips on a ReDoS pattern.
        const val MIN_CHAR_BUDGET = 5_000_000L
        const val PER_CHAR_BUDGET = 4_000L
    }

    private class RegexBudgetExceededException : RuntimeException()

    /**
     * A read-only CharSequence view that counts character reads and throws once a budget is
     * exceeded. java.util.regex does not honour thread interruption, so this is how a runaway
     * match is actually stopped: every backtrack step reads characters through [get].
     */
    private class BudgetedCharSequence(
        private val s: CharSequence,
        private val budget: Long,
        private val counter: LongArray = LongArray(1),
    ) : CharSequence {
        override val length: Int get() = s.length
        override fun get(index: Int): Char {
            if (++counter[0] > budget) throw RegexBudgetExceededException()
            return s[index]
        }
        override fun subSequence(startIndex: Int, endIndex: Int): CharSequence =
            BudgetedCharSequence(s.subSequence(startIndex, endIndex), budget, counter)
        override fun toString(): String = s.toString()
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
