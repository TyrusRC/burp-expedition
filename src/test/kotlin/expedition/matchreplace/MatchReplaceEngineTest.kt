package expedition.matchreplace

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class MatchReplaceEngineTest {

    @Test
    fun `applies a literal string rule`() {
        val engine = MatchReplaceEngine()
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar"))

        val result = engine.apply("foo baz foo".toByteArray())

        assertArrayEquals("bar baz bar".toByteArray(), result)
    }

    @Test
    fun `applies a regex rule`() {
        val engine = MatchReplaceEngine()
        engine.addRule(MatchReplaceRule(1, MatchType.REGEX, "\\d+", "N"))

        val result = engine.apply("id=123 count=45".toByteArray())

        assertArrayEquals("id=N count=N".toByteArray(), result)
    }

    @Test
    fun `applies a literal bytes rule expressed as hex`() {
        val engine = MatchReplaceEngine()
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_BYTES, "0102", "ff"))

        val result = engine.apply(byteArrayOf(0x01, 0x02, 0x03))

        assertArrayEquals(byteArrayOf(0xff.toByte(), 0x03), result)
    }

    @Test
    fun `disabled rules are not applied`() {
        val engine = MatchReplaceEngine()
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar", enabled = false))

        val result = engine.apply("foo".toByteArray())

        assertArrayEquals("foo".toByteArray(), result)
    }

    @Test
    fun `rules apply in the order they were added`() {
        val engine = MatchReplaceEngine()
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "a", "b"))
        engine.addRule(MatchReplaceRule(2, MatchType.LITERAL_STRING, "b", "c"))

        val result = engine.apply("a".toByteArray())

        assertArrayEquals("c".toByteArray(), result)
    }

    @Test
    fun `removeRule drops a rule by id`() {
        val engine = MatchReplaceEngine()
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar"))
        engine.removeRule(1)

        val result = engine.apply("foo".toByteArray())

        assertArrayEquals("foo".toByteArray(), result)
    }
}
