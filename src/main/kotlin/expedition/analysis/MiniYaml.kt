package expedition.analysis

/**
 * Minimal YAML reader sufficient for OpenAPI documents: block mappings and sequences,
 * flow `[..]`/`{..}` collections on one line, quoted/plain scalars, `|`/`>` block scalars
 * and comments. No anchors, tags or multi-document streams. Numbers parse as Double and
 * mappings as LinkedHashMap, matching [expedition.server.Json.parse].
 */
object MiniYaml {
    private class Line(val indent: Int, val text: String)

    fun parse(text: String): Any? {
        val lines = ArrayList<Line>()
        for (raw in text.replace("\t", "  ").lines()) {
            val stripped = stripComment(raw).trimEnd()
            if (stripped.isBlank() || stripped.trim() == "---" || stripped.trim() == "...") continue
            if (stripped.trimStart().startsWith("%")) continue
            lines.add(Line(stripped.length - stripped.trimStart().length, stripped.trim()))
        }
        if (lines.isEmpty()) return null
        val p = P(lines)
        val v = p.block(lines[0].indent)
        require(p.i >= lines.size) { "yaml: unexpected content at line ${p.i + 1}" }
        return v
    }

    private fun stripComment(s: String): String {
        var q = '\u0000'
        for (i in s.indices) {
            val c = s[i]
            if (q != '\u0000') { if (c == q) q = '\u0000'; continue }
            if (c == '"' || c == '\'') { if (i == 0 || s[i - 1] in " :[{,-") q = c }
            else if (c == '#' && (i == 0 || s[i - 1] == ' ')) return s.substring(0, i)
        }
        return s
    }

    private class P(val lines: MutableList<Line>) {
        var i = 0

        fun block(indent: Int): Any? {
            val t = lines[i].text
            return if (t == "-" || t.startsWith("- ")) seq(indent) else if (keySplit(t) != null) map(indent) else scalarLines(indent)
        }

        private fun scalarLines(indent: Int): Any? {
            val sb = StringBuilder(lines[i].text); i++
            while (i < lines.size && lines[i].indent > indent - 1 && lines[i].indent >= indent) { sb.append(' ').append(lines[i].text); i++ }
            return inline(sb.toString())
        }

        private fun seq(indent: Int): List<Any?> {
            val out = ArrayList<Any?>()
            while (i < lines.size && lines[i].indent == indent && (lines[i].text == "-" || lines[i].text.startsWith("- "))) {
                val t = lines[i].text
                val rest = t.removePrefix("-").trimStart()
                if (rest.isEmpty()) {
                    i++
                    out.add(if (i < lines.size && lines[i].indent > indent) block(lines[i].indent) else null)
                } else {
                    val off = t.length - rest.length
                    lines[i] = Line(indent + off, rest)
                    out.add(if (rest == "-" || rest.startsWith("- ") || keySplit(rest) != null) block(indent + off) else { i++; inline(rest) })
                }
            }
            return out
        }

        private fun map(indent: Int): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            while (i < lines.size && lines[i].indent == indent) {
                val t = lines[i].text
                val kv = keySplit(t) ?: throw IllegalArgumentException("yaml: expected 'key: value' at line ${i + 1}: $t")
                val (key, rest) = kv
                i++
                m[key] = when {
                    rest.isEmpty() -> when {
                        i < lines.size && lines[i].indent > indent -> block(lines[i].indent)
                        i < lines.size && lines[i].indent == indent && (lines[i].text == "-" || lines[i].text.startsWith("- ")) -> seq(indent)
                        else -> null
                    }
                    rest.startsWith("|") || rest.startsWith(">") -> blockScalar(indent, rest.startsWith(">"))
                    rest.startsWith("[") || rest.startsWith("{") || rest.startsWith("\"") || rest.startsWith("'") -> inline(rest)
                    else -> {
                        val sb = StringBuilder(rest)
                        while (i < lines.size && lines[i].indent > indent) { sb.append(' ').append(lines[i].text); i++ }
                        inline(sb.toString())
                    }
                }
            }
            return m
        }

        private fun blockScalar(indent: Int, fold: Boolean): String {
            val parts = ArrayList<String>()
            while (i < lines.size && lines[i].indent > indent) { parts.add(lines[i].text); i++ }
            return parts.joinToString(if (fold) " " else "\n")
        }
    }

    /** Splits `key: rest` (key may be quoted); null when the line is not a mapping entry. */
    private fun keySplit(t: String): Pair<String, String>? {
        if (t.startsWith("\"") || t.startsWith("'")) {
            val q = t[0]; var j = 1
            while (j < t.length && t[j] != q) { if (q == '"' && t[j] == '\\') j++; j++ }
            if (j >= t.length) return null
            val after = t.substring(j + 1).trimStart()
            if (!after.startsWith(":")) return null
            return (inline(t.substring(0, j + 1)) as? String ?: t.substring(1, j)) to after.substring(1).trim()
        }
        if (t.startsWith("[") || t.startsWith("{")) return null
        val idx = t.indexOf(": ").let { if (it >= 0) it else if (t.endsWith(":")) t.length - 1 else -1 }
        if (idx <= 0) return null
        return t.substring(0, idx).trim() to t.substring(idx + 1).trim()
    }

    private fun inline(s0: String): Any? {
        val s = s0.trim()
        val f = Flow(s)
        val v = f.value()
        f.ws()
        if (f.i < s.length) return s // plain scalar containing odd characters
        return v
    }

    private class Flow(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i] == ' ') i++ }
        fun value(): Any? {
            ws()
            if (i >= s.length) return null
            return when (s[i]) {
                '[' -> { i++; val a = ArrayList<Any?>(); ws()
                    if (i < s.length && s[i] == ']') { i++; return a }
                    while (true) { a.add(value()); ws()
                        require(i < s.length) { "yaml: unterminated flow sequence" }
                        if (s[i] == ',') { i++; ws(); if (i < s.length && s[i] == ']') { i++; return a } } else if (s[i] == ']') { i++; return a } else throw IllegalArgumentException("yaml: bad flow sequence") } ; @Suppress("UNREACHABLE_CODE") a }
                '{' -> { i++; val m = LinkedHashMap<String, Any?>(); ws()
                    if (i < s.length && s[i] == '}') { i++; return m }
                    while (true) { ws()
                        val k = value()?.toString() ?: ""; ws()
                        require(i < s.length && s[i] == ':') { "yaml: bad flow mapping" }; i++
                        m[k] = value(); ws()
                        require(i < s.length) { "yaml: unterminated flow mapping" }
                        if (s[i] == ',') { i++ } else if (s[i] == '}') { i++; return m } else throw IllegalArgumentException("yaml: bad flow mapping") } ; @Suppress("UNREACHABLE_CODE") m }
                '"' -> { i++; val sb = StringBuilder()
                    while (i < s.length && s[i] != '"') {
                        if (s[i] == '\\' && i + 1 < s.length) { i++
                            when (val e = s[i]) { 'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r'); '0' -> sb.append('\u0000')
                                'u' -> { sb.append(s.substring(i + 1, i + 5).toInt(16).toChar()); i += 4 }
                                else -> sb.append(e) }
                        } else sb.append(s[i])
                        i++ }
                    require(i < s.length) { "yaml: unterminated string" }; i++; sb.toString() }
                '\'' -> { i++; val sb = StringBuilder()
                    while (i < s.length) {
                        if (s[i] == '\'') { if (i + 1 < s.length && s[i + 1] == '\'') { sb.append('\''); i += 2; continue } else break }
                        sb.append(s[i]); i++ }
                    require(i < s.length) { "yaml: unterminated string" }; i++; sb.toString() }
                else -> {
                    val inFlow = s.startsWith("[") || s.startsWith("{")
                    val start = i
                    while (i < s.length && !(inFlow && s[i] in ",]}") && !(inFlow && s[i] == ':' && (i + 1 >= s.length || s[i + 1] == ' '))) i++
                    plain(s.substring(start, i).trim())
                }
            }
        }
        private fun plain(t: String): Any? = when {
            t == "" || t == "~" || t == "null" || t == "Null" || t == "NULL" -> null
            t == "true" || t == "True" || t == "TRUE" -> true
            t == "false" || t == "False" || t == "FALSE" -> false
            NUM.matches(t) -> t.toDouble()
            else -> t
        }
    }

    private val NUM = Regex("^[-+]?(\\d+\\.?\\d*|\\.\\d+)([eE][-+]?\\d+)?$")
}
