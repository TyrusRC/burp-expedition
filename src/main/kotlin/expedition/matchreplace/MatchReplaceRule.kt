package expedition.matchreplace

enum class MatchType { LITERAL_BYTES, LITERAL_STRING, REGEX }

data class MatchReplaceRule(
    val id: Long,
    val matchType: MatchType,
    val matchValue: String,
    val replaceValue: String,
    val enabled: Boolean = true,
    /**
     * When true, the rule is applied to the dissector's DECODED text view and the result
     * is re-encoded (fixing length prefixes/framing), instead of matching raw bytes.
     * Only LITERAL_STRING and REGEX make sense here. Requires a DissectorRegistry on the engine.
     */
    val decoded: Boolean = false
) {
    /**
     * REGEX rules compile their pattern ONCE here, so [MatchReplaceEngine.apply] reuses it
     * per message instead of recompiling on every byte buffer on a Netty worker thread.
     * null for non-regex rules. A malformed pattern throws from this initializer, i.e. at
     * construction — which is the point: both the UI form and the Control API build rules
     * through this constructor, so neither can introduce a rule that explodes mid-traffic.
     */
    val regex: Regex? = if (matchType == MatchType.REGEX) {
        try {
            Regex(matchValue)
        } catch (e: java.util.regex.PatternSyntaxException) {
            throw IllegalArgumentException("Invalid regex: ${e.message}")
        }
    } else {
        null
    }

    init {
        // LITERAL_BYTES match/replace values are parsed as hex pairs by the engine; reject
        // malformed hex here rather than letting NumberFormatException/StringIndex escape
        // from hexToBytes() on a worker thread. An empty replacement is allowed (deletion).
        if (matchType == MatchType.LITERAL_BYTES) {
            require(isHexPairs(matchValue) && stripWs(matchValue).isNotEmpty()) {
                "Literal bytes match must be hex pairs, e.g. '48 65 6c'"
            }
            require(isHexPairs(replaceValue)) {
                "Literal bytes replacement must be hex pairs (or empty)"
            }
        }
    }

    private companion object {
        fun stripWs(s: String) = s.filterNot(Char::isWhitespace)
        fun isHexPairs(s: String): Boolean {
            val clean = stripWs(s)
            return clean.length % 2 == 0 && clean.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
        }
    }
}
