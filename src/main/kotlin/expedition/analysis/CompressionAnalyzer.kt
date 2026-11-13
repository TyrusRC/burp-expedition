package expedition.analysis

import java.util.zip.Deflater

/**
 * Content-Encoding / Accept-Encoding analysis for one exchange: estimates gzip savings for
 * uncompressed text, reports actual ratios for compressed bodies and flags missing
 * `Vary: Accept-Encoding`. Brotli/zstd are only recognised (no decoder is bundled).
 */
object CompressionAnalyzer {
    const val MIN_SIZE = 1024
    const val SAMPLE = 256 * 1024
    private const val SAVINGS_WARN_PCT = 20

    fun analyze(x: HttpExchange): List<Finding> {
        val res = x.response ?: return emptyList()
        val out = ArrayList<Finding>()
        fun add(sev: Severity, code: String, msg: String) =
            out.add(Finding(x.connectionId, x.label, "compression", sev, code, msg))

        val encs = (res.header("content-encoding") ?: "").split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() && it != "identity" }
        val accept = parseAccept(x.request.header("accept-encoding"))
        val ct = res.contentType
        val size = res.body.size

        if (encs.isEmpty()) {
            if (size < MIN_SIZE || res.truncated && size < MIN_SIZE) return out
            if (!isCompressible(ct)) return out
            val est = estimateGzip(res.body)
            val pct = ((size - est) * 100.0 / size).toInt()
            val acceptsGzip = accept.containsKey("gzip") || accept.containsKey("*") || accept.containsKey("deflate")
            if (pct >= SAVINGS_WARN_PCT) {
                add(
                    if (acceptsGzip) Severity.WARNING else Severity.INFO, "compression.uncompressed-text",
                    "Uncompressed ${ct ?: "text"} body of $size bytes; gzip would be ~$est bytes (saves ~$pct%)" +
                        if (acceptsGzip) "" else " (client did not advertise gzip/deflate in Accept-Encoding)",
                )
            } else {
                add(Severity.INFO, "compression.low-gain", "Uncompressed body of $size bytes; estimated gzip gain only ~$pct%")
            }
            return out
        }

        // Compressed response.
        val label = encs.joinToString(", ")
        for (e in encs) if (accept.isNotEmpty() && !accepts(accept, e)) {
            add(Severity.ERROR, "compression.not-accepted", "Response uses Content-Encoding '$e' but the request's Accept-Encoding does not allow it")
        } else if (accept.isEmpty() && x.request.header("accept-encoding") == null) {
            add(Severity.WARNING, "compression.unrequested", "Response uses Content-Encoding '$e' although the request sent no Accept-Encoding")
            break
        }
        val vary = res.header("vary")?.lowercase()?.split(',')?.map { it.trim() } ?: emptyList()
        if ("*" !in vary && "accept-encoding" !in vary) {
            add(Severity.WARNING, "compression.no-vary", "Compressed response ($label) lacks 'Vary: Accept-Encoding'; shared caches may serve it to clients that cannot decode it")
        }
        if (ct != null && isAlreadyCompressed(ct)) {
            add(Severity.INFO, "compression.double", "Content-Encoding '$label' applied to already-compressed type $ct; usually wasted CPU")
        }
        val known = encs.all { it in setOf("gzip", "x-gzip", "deflate") }
        if (known) {
            val dec = HttpExchanges.decodedBody(res)
            if (dec != null && dec.isNotEmpty() && !res.truncated && dec.size < HttpExchanges.MAX_DECODED) {
                val pct = ((dec.size - size) * 100.0 / dec.size).toInt()
                add(Severity.INFO, "compression.ratio", "$label: $size bytes on the wire for ${dec.size} decoded bytes (saves $pct%)")
            }
        } else {
            add(Severity.INFO, "compression.detected", "Content-Encoding '$label' detected (no decoder bundled; savings not measured)")
        }
        return out
    }

    /** Estimates the gzip size of [body] by deflating up to [SAMPLE] bytes and scaling. */
    fun estimateGzip(body: ByteArray): Int {
        val n = minOf(body.size, SAMPLE)
        val d = Deflater(6)
        try {
            d.setInput(body, 0, n); d.finish()
            val buf = ByteArray(8192); var total = 0L
            while (!d.finished()) total += d.deflate(buf)
            val scaled = if (n == body.size) total else total * body.size / n
            return (scaled + 18).toInt() // gzip header + trailer
        } finally { d.end() }
    }

    fun parseAccept(h: String?): Map<String, Double> {
        if (h == null) return emptyMap()
        val m = LinkedHashMap<String, Double>()
        for (part in h.split(',')) {
            val p = part.trim(); if (p.isEmpty()) continue
            val name = p.substringBefore(';').trim().lowercase()
            val q = Regex("q\\s*=\\s*([0-9.]+)").find(p)?.groupValues?.get(1)?.toDoubleOrNull() ?: 1.0
            m[name] = q
        }
        return m
    }

    private fun accepts(accept: Map<String, Double>, enc: String): Boolean {
        val name = if (enc == "x-gzip") "gzip" else enc
        val q = accept[name] ?: accept["*"] ?: return false
        return q > 0.0
    }

    fun isCompressible(ct: String?): Boolean {
        if (ct == null) return false
        return ct.startsWith("text/") || listOf("json", "xml", "javascript", "ecmascript", "svg", "yaml", "x-www-form-urlencoded", "wasm", "graphql").any { ct.contains(it) }
    }

    private fun isAlreadyCompressed(ct: String): Boolean =
        ct.startsWith("image/") && !ct.contains("svg") && !ct.contains("bmp") || ct.startsWith("video/") || ct.startsWith("audio/") ||
            ct in setOf("application/zip", "application/gzip", "application/pdf", "font/woff", "font/woff2", "application/x-7z-compressed")
}
