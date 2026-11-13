package expedition.engine.tls

import expedition.tls.BurpCertificateProvider

/**
 * Host patterns whose TLS is relayed untouched (no MITM). A pattern is either an exact host
 * (`api.example.com`) or a suffix wildcard (`*.example.com`, which matches any depth of
 * subdomain — `a.example.com`, `a.b.example.com` — but not `example.com` itself).
 * Matching is case-insensitive and ignores a trailing dot.
 */
class TlsPassthroughMatcher(patterns: List<String>) {
    private val exact: Set<String>
    private val suffixes: List<String>

    init {
        val normalized = patterns.map { it.trim().lowercase().removeSuffix(".") }.filter { it.isNotEmpty() }
        normalized.forEach { require(isValidPattern(it)) { "invalid tls_passthrough pattern '$it' (use host or *.suffix)" } }
        exact = normalized.filterNot { it.startsWith("*.") }.toSet()
        suffixes = normalized.filter { it.startsWith("*.") }.map { it.substring(1) } // keep the leading "."
    }

    val isEmpty: Boolean get() = exact.isEmpty() && suffixes.isEmpty()

    fun matches(host: String?): Boolean {
        if (host == null || isEmpty) return false
        val h = BurpCertificateProvider.normalizeHost(host)
        if (h.isEmpty()) return false
        return h in exact || suffixes.any { h.endsWith(it) && h.length > it.length }
    }

    companion object {
        fun isValidPattern(p: String): Boolean {
            val body = p.trim().lowercase().removeSuffix(".").let { if (it.startsWith("*.")) it.substring(2) else it }
            return BurpCertificateProvider.isValidHostName(body)
        }
    }
}
