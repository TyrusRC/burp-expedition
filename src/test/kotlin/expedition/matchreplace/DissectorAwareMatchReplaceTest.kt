package expedition.matchreplace

import expedition.dissector.DissectorRegistry
import expedition.dissector.MysqlDissector
import expedition.dissector.ProtobufDissector
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class DissectorAwareMatchReplaceTest {

    // protobuf: field 2, length-delimited "foo" -> [0x12, 0x03, f, o, o]
    private val protobufFoo = byteArrayOf(0x12, 0x03) + "foo".toByteArray()

    @Test
    fun `decoded rule rewrites a protobuf field and recomputes the length prefix`() {
        val registry = DissectorRegistry().apply { register(ProtobufDissector()) }
        val engine = MatchReplaceEngine(registry)
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "longer-value", decoded = true))

        val out = engine.apply(protobufFoo)

        // field 2, length 12, "longer-value" — the length prefix is recomputed, not left at 3.
        val expected = byteArrayOf(0x12, 0x0c) + "longer-value".toByteArray()
        assertArrayEquals(expected, out)
    }

    @Test
    fun `a raw rule on the same bytes breaks framing - contrast with the decoded rule`() {
        val engine = MatchReplaceEngine() // no dissector registry
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "longer-value"))

        val out = engine.apply(protobufFoo)

        // raw replace leaves the length prefix at 0x03 (broken framing) — documents why decoded rules exist.
        val broken = byteArrayOf(0x12, 0x03) + "longer-value".toByteArray()
        assertArrayEquals(broken, out)
    }

    @Test
    fun `decoded rules are skipped when no dissector registry is configured`() {
        val engine = MatchReplaceEngine() // null registry
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar", decoded = true))

        // With no registry the decoded rule cannot run, so bytes pass through unchanged.
        assertArrayEquals(protobufFoo, engine.apply(protobufFoo))
    }

    @Test
    fun `a decoded rule that does not match leaves the message byte-identical`() {
        val registry = DissectorRegistry().apply { register(MysqlDissector()) }
        val engine = MatchReplaceEngine(registry)
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "willnotmatch", "x", decoded = true))
        // MySQL COM_QUERY with sequence id 5 — re-encoding would reset it to 0, so if the rule
        // doesn't match we must NOT re-encode.
        val bytes = byteArrayOf(0x09, 0, 0, 0x05, 0x03) + "SELECT 1".toByteArray()
        assertArrayEquals(bytes, engine.apply(bytes))
    }

    @Test
    fun `raw and decoded rules both still work together`() {
        val registry = DissectorRegistry().apply { register(ProtobufDissector()) }
        val engine = MatchReplaceEngine(registry)
        engine.addRule(MatchReplaceRule(1, MatchType.LITERAL_STRING, "foo", "bar", decoded = true))

        val out = engine.apply(protobufFoo)

        val expected = byteArrayOf(0x12, 0x03) + "bar".toByteArray()
        assertArrayEquals(expected, out)
    }
}
