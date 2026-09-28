package expedition.server

/**
 * Minimal zero-dependency JSON — the control API's only serialization needs are
 * flat objects and arrays of primitives, so a tiny hand-rolled writer + a
 * recursive-descent parser avoid pulling a JSON library into the shaded jar
 * (the extension keeps its runtime deps to Netty + Bouncy Castle).
 *
 * Writer: `obj(...)` / `arr(...)` build strings with correct escaping.
 * Parser: `parse(text)` returns Map<String,Any?> / List<Any?> / String / Double
 * / Boolean / null; `asObject` / `str` / `int` read fields with defaults.
 */
object Json {

    // ── Writer ────────────────────────────────────────────────────────────
    fun escape(s: String): String {
        val sb = StringBuilder(s.length + 8)
        for (c in s) when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
        return sb.toString()
    }

    fun value(v: Any?): String = when (v) {
        null -> "null"
        is Boolean -> v.toString()
        is Int, is Long, is Double, is Float -> v.toString()
        is Map<*, *> -> obj(v.entries.associate { it.key.toString() to it.value })
        is List<*> -> arr(v)
        else -> "\"${escape(v.toString())}\""
    }

    fun obj(map: Map<String, Any?>): String =
        map.entries.joinToString(",", "{", "}") { "\"${escape(it.key)}\":${value(it.value)}" }

    fun obj(vararg pairs: Pair<String, Any?>): String = obj(pairs.toMap())

    fun arr(items: List<Any?>): String = items.joinToString(",", "[", "]") { value(it) }

    // ── Parser ────────────────────────────────────────────────────────────
    fun parse(text: String): Any? = Parser(text).parseValue().also { }

    @Suppress("UNCHECKED_CAST")
    fun asObject(v: Any?): Map<String, Any?> = (v as? Map<String, Any?>) ?: emptyMap()

    fun str(o: Map<String, Any?>, key: String, default: String = ""): String =
        (o[key]?.toString()) ?: default

    fun int(o: Map<String, Any?>, key: String, default: Int = 0): Int = when (val x = o[key]) {
        is Number -> x.toInt()
        is String -> x.toIntOrNull() ?: default
        else -> default
    }

    private class Parser(private val s: String) {
        private var i = 0
        fun parseValue(): Any? {
            skipWs()
            return when (val c = peek()) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't', 'f' -> parseBool()
                'n' -> { expect("null"); null }
                else -> if (c == '-' || c.isDigit()) parseNumber()
                        else throw IllegalArgumentException("unexpected char '$c' at $i")
            }
        }
        private fun parseObject(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>(); expectChar('{'); skipWs()
            if (peek() == '}') { i++; return m }
            while (true) {
                skipWs(); val k = parseString(); skipWs(); expectChar(':')
                m[k] = parseValue(); skipWs()
                when (next()) { ',' -> {}; '}' -> return m; else -> throw IllegalArgumentException("bad object at $i") }
            }
        }
        private fun parseArray(): List<Any?> {
            val a = ArrayList<Any?>(); expectChar('['); skipWs()
            if (peek() == ']') { i++; return a }
            while (true) {
                a.add(parseValue()); skipWs()
                when (next()) { ',' -> {}; ']' -> return a; else -> throw IllegalArgumentException("bad array at $i") }
            }
        }
        private fun parseString(): String {
            expectChar('"'); val sb = StringBuilder()
            while (true) {
                when (val c = next()) {
                    '"' -> return sb.toString()
                    '\\' -> when (val e = next()) {
                        '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                        'n' -> sb.append('\n'); 'r' -> sb.append('\r'); 't' -> sb.append('\t')
                        'b' -> sb.append('\b'); 'f' -> sb.append('\u000C')
                        'u' -> { val hex = s.substring(i, i + 4); i += 4; sb.append(hex.toInt(16).toChar()) }
                        else -> throw IllegalArgumentException("bad escape \\$e")
                    }
                    else -> sb.append(c)
                }
            }
        }
        private fun parseNumber(): Double {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] in "-+.eE")) i++
            return s.substring(start, i).toDouble()
        }
        private fun parseBool(): Boolean =
            if (s.startsWith("true", i)) { i += 4; true } else { expect("false"); false }
        private fun expect(w: String) {
            require(s.startsWith(w, i)) { "expected '$w' at $i" }; i += w.length
        }
        private fun peek(): Char { skipWs(); return if (i < s.length) s[i] else '\u0000' }
        private fun next(): Char = s[i++]
        private fun expectChar(c: Char) { skipWs(); require(i < s.length && s[i] == c) { "expected '$c' at $i" }; i++ }
        private fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
    }
}
