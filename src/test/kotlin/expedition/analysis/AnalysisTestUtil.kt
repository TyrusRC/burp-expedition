package expedition.analysis

internal fun exch(req: String, res: String?, id: Long = 1): HttpExchange {
    fun fix(s: String) = s.replace("\r\n", "\n").replace("\n", "\r\n")
    val r = HttpExchanges.parseStream(fix(req).toByteArray(Charsets.ISO_8859_1), true, emptyList())
    val methods = r.map { it.method }
    val s = res?.let { HttpExchanges.parseStream(fix(it).toByteArray(Charsets.ISO_8859_1), false, methods) }
    return HttpExchange(id, r[0], s?.getOrNull(0))
}

/** Builds a raw HTTP response with a Content-Length computed from [body]. */
internal fun resp(status: Int, headers: String, body: String): String =
    "HTTP/1.1 $status X\r\n" + headers.trim().lines().filter { it.isNotBlank() }.joinToString("") { it.trim() + "\r\n" } +
        "Content-Length: ${body.toByteArray().size}\r\n\r\n$body"
