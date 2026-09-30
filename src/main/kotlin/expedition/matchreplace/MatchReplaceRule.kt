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
)
