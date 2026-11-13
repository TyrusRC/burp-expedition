package expedition.analysis

import java.time.Duration
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/** Cache semantics (RFC 9111) of one exchange: cacheability, freshness lifetime and misconfigurations. */
object CacheAnalyzer {
    /** Outcome of [verdict]. [scope] is "shared", "private" or "none"; [ttlSeconds] null when no freshness info. */
    data class Verdict(val cacheable: Boolean, val scope: String, val ttlSeconds: Long?, val basis: String)

    private val HEURISTIC_STATUS = setOf(200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501)

    fun parseCacheControl(h: String?): Map<String, String?> {
        if (h == null) return emptyMap()
        val m = LinkedHashMap<String, String?>()
        val parts = ArrayList<String>(); val sb = StringBuilder(); var q = false
        for (c in h) { if (c == '"') q = !q; if (c == ',' && !q) { parts.add(sb.toString()); sb.setLength(0) } else sb.append(c) }
        parts.add(sb.toString())
        for (p in parts) {
            val t = p.trim(); if (t.isEmpty()) continue
            val k = t.substringBefore('=').trim().lowercase()
            m[k] = if (t.contains('=')) t.substringAfter('=').trim().trim('"') else null
        }
        return m
    }

    private fun date(h: String?): ZonedDateTime? = h?.let {
        try { ZonedDateTime.parse(it.trim(), DateTimeFormatter.RFC_1123_DATE_TIME) } catch (_: Exception) { null }
    }

    private fun secs(v: String?): Long? = v?.trim()?.toLongOrNull()?.takeIf { it >= 0 }

    fun verdict(x: HttpExchange): Verdict? {
        val res = x.response ?: return null
        val cc = parseCacheControl(res.header("cache-control"))
        val method = x.request.method
        if (method != "GET" && method != "HEAD") return Verdict(false, "none", null, "method $method is not cacheable by default")
        if ("no-store" in cc) return Verdict(false, "none", null, "Cache-Control: no-store")
        val explicit = cc.containsKey("max-age") || cc.containsKey("s-maxage") || res.header("expires") != null
        if (res.status !in HEURISTIC_STATUS && !explicit && "public" !in cc) {
            return Verdict(false, "none", null, "status ${res.status} is not cacheable without explicit freshness")
        }
        val scope = if ("private" in cc) "private" else "shared"
        val sMax = secs(cc["s-maxage"]); val max = secs(cc["max-age"])
        val dateH = date(res.header("date"))
        var ttl: Long?; var basis: String
        when {
            scope == "shared" && sMax != null -> { ttl = sMax; basis = "s-maxage" }
            max != null -> { ttl = max; basis = "max-age" }
            res.header("expires") != null -> {
                val exp = date(res.header("expires"))
                val base = dateH ?: ZonedDateTime.now()
                ttl = if (exp == null) 0 else maxOf(0L, Duration.between(base, exp).seconds); basis = "Expires" + if (exp == null) " (invalid, treated as expired)" else ""
            }
            else -> {
                val lm = date(res.header("last-modified"))
                if (lm != null && dateH != null && !dateH.isBefore(lm)) {
                    ttl = Duration.between(lm, dateH).seconds / 10; basis = "heuristic (10% of Last-Modified age)"
                } else { ttl = null; basis = "no freshness information" }
            }
        }
        val age = secs(res.header("age"))
        if (ttl != null && age != null) ttl = maxOf(0L, ttl - age).also { basis += ", minus Age=$age" }
        if ("no-cache" in cc) return Verdict(true, scope, 0, "$basis; no-cache forces revalidation")
        return Verdict(true, scope, ttl, basis)
    }

    fun analyze(x: HttpExchange): List<Finding> {
        val res = x.response ?: return emptyList()
        val out = ArrayList<Finding>()
        fun add(sev: Severity, code: String, msg: String) = out.add(Finding(x.connectionId, x.label, "cache", sev, code, msg))
        val cc = parseCacheControl(res.header("cache-control"))
        val etag = res.header("etag"); val lm = res.header("last-modified")
        val hasValidator = etag != null || lm != null
        val hasCookie = res.header("set-cookie") != null
        val hasAuth = x.request.header("authorization") != null
        val vary = res.header("vary")?.lowercase()?.split(',')?.map { it.trim() } ?: emptyList()
        val v = verdict(x)!!

        if (x.request.method == "GET" || x.request.method == "HEAD") {
            val ttlText = when {
                !v.cacheable -> ""
                v.ttlSeconds == null -> ", no TTL"
                else -> ", TTL ${v.ttlSeconds}s"
            }
            add(Severity.INFO, "cache.summary",
                (if (v.cacheable) "Cacheable (${v.scope})" else "Not cacheable") + "$ttlText [${v.basis}]")
        }
        if ("no-store" in cc && hasValidator) add(Severity.WARNING, "cache.no-store-with-validator", "no-store together with ${listOfNotNull(etag?.let { "ETag" }, lm?.let { "Last-Modified" }).joinToString("/")}: validators are useless because nothing may be stored")
        if ("no-store" in cc && (cc.containsKey("max-age") || cc.containsKey("s-maxage"))) add(Severity.WARNING, "cache.no-store-with-max-age", "no-store conflicts with max-age/s-maxage; no-store wins")
        if ("public" in cc && hasCookie) add(Severity.WARNING, "cache.public-set-cookie", "Cache-Control: public on a response with Set-Cookie; a shared cache could replay the cookie to other users")
        if ("public" in cc && hasAuth && "no-store" !in cc) add(Severity.WARNING, "cache.public-authorization", "Cache-Control: public on a response to a request carrying Authorization")
        if (v.cacheable && v.scope == "shared" && hasCookie && "public" !in cc && (v.ttlSeconds ?: 0) > 0) {
            add(Severity.WARNING, "cache.shared-set-cookie", "Cacheable by shared caches with a positive TTL but sets a cookie; add 'private' or 'no-store'")
        }
        if ("private" in cc && "public" in cc) add(Severity.WARNING, "cache.public-and-private", "Both public and private present; contradictory")
        if ("immutable" in cc && cc["max-age"] == null) add(Severity.INFO, "cache.immutable-without-max-age", "immutable has no effect without max-age")
        if (v.cacheable && !hasValidator && "no-store" !in cc && x.request.method == "GET") {
            add(Severity.INFO, "cache.no-validator", "No ETag or Last-Modified: stale copies cannot be revalidated with a conditional request")
        }
        if (v.cacheable && (v.ttlSeconds == null) && !hasValidator && res.status == 200 && cc.isEmpty()) {
            add(Severity.INFO, "cache.no-headers", "No caching headers at all; clients and proxies will guess or refetch")
        }
        if (cc.isEmpty() && lm != null && res.header("expires") == null) add(Severity.INFO, "cache.heuristic-only", "Only Last-Modified present: caches will apply heuristic freshness; set explicit Cache-Control")
        if (res.header("pragma") != null && cc.isEmpty()) add(Severity.INFO, "cache.pragma-only", "Pragma without Cache-Control is obsolete for responses")
        if ("*" in vary) add(Severity.WARNING, "cache.vary-star", "Vary: * makes every response uncacheable by shared caches")
        if ("cookie" in vary && "public" in cc) add(Severity.INFO, "cache.vary-cookie", "Vary: Cookie with public fragments the shared cache per user")
        if (res.header("expires")?.let { date(it) == null } == true) add(Severity.WARNING, "cache.invalid-expires", "Expires is not a valid HTTP date and is treated as already expired")
        if (cc["max-age"]?.let { secs(it) == null } == true) add(Severity.WARNING, "cache.invalid-max-age", "max-age has a non-numeric or negative value")
        val ma = secs(cc["max-age"]); val age = secs(res.header("age"))
        if (ma != null && age != null && age > ma) add(Severity.INFO, "cache.stale", "Age ($age) exceeds max-age ($ma): the response was served stale")
        if ((ma == 0L) && !hasValidator && "no-store" !in cc && "no-cache" !in cc) add(Severity.INFO, "cache.max-age-zero-no-validator", "max-age=0 without validator forces a full refetch every time")
        return out
    }
}
