package expedition.matchreplace

enum class MatchType { LITERAL_BYTES, LITERAL_STRING, REGEX }

data class MatchReplaceRule(
    val id: Long,
    val matchType: MatchType,
    val matchValue: String,
    val replaceValue: String,
    val enabled: Boolean = true
)
