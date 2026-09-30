package expedition.ui

import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import java.util.regex.PatternSyntaxException

object MatchReplaceFormValidation {
    fun validate(
        matchType: MatchType,
        matchValue: String,
        replaceValue: String,
        nextId: Long,
        decoded: Boolean = false
    ): Result<MatchReplaceRule> {
        if (matchValue.isBlank()) return Result.failure(IllegalArgumentException("Match value must not be blank"))
        if (matchType == MatchType.REGEX) {
            try {
                Regex(matchValue)
            } catch (e: PatternSyntaxException) {
                return Result.failure(IllegalArgumentException("Invalid regex: ${e.message}"))
            }
        }
        if (matchType == MatchType.LITERAL_BYTES && !matchValue.matches(Regex("^([0-9a-fA-F]{2}\\s*)+$"))) {
            return Result.failure(IllegalArgumentException("Literal bytes must be hex pairs, e.g. '48 65 6c'"))
        }
        if (decoded && matchType == MatchType.LITERAL_BYTES) {
            return Result.failure(IllegalArgumentException("Decoded rules operate on text; use LITERAL_STRING or REGEX"))
        }
        return Result.success(MatchReplaceRule(nextId, matchType, matchValue, replaceValue, decoded = decoded))
    }
}
