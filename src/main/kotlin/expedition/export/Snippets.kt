package expedition.export

import expedition.analysis.HttpExchanges
import java.util.Base64

/** A parsed HTTP request ready to be rendered as code. Host and Content-Length headers are dropped. */
class SnippetRequest(
    val method: String,
    val url: String,
    val headers: List<Pair<String, String>>,
    val body: ByteArray,
) {
    /** Body as text when it is valid UTF-8 without NULs, else null (then generators emit it base64/hex-encoded). */
    val bodyText: String? = if (body.isEmpty()) "" else HarCodec.strictUtf8(body)
    val hasBody: Boolean get() = body.isNotEmpty()
    val isBinary: Boolean get() = hasBody && bodyText == null
    val base64: String get() = Base64.getEncoder().encodeToString(body)
    val scheme: String
    val authority: String
    /** Path plus query, "/" when empty. */
    val target: String
    val hostname: String
    val port: Int?
    val isHttps: Boolean get() = scheme == "https"

    init {
        val t = HarCodec.splitUrl(url)
        scheme = t?.first ?: "http"
        authority = t?.second ?: ""
        target = t?.third ?: "/"
        val (h, p) = if (t != null) HarCodec.splitAuthority(authority, scheme) else ("" to 80)
        hostname = h.removePrefix("[").removeSuffix("]")
        port = if (authority.endsWith("]") || !authority.substringAfterLast(':', "").all { it.isDigit() } || !authority.contains(':')) null
               else p
    }

    fun header(name: String) = headers.firstOrNull { it.first.equals(name, true) }?.second

    /** Headers with duplicate names folded (", " joined; "; " for Cookie), first-seen order. */
    val mergedHeaders: List<Pair<String, String>> by lazy {
        val m = LinkedHashMap<String, Pair<String, String>>()
        for ((n, v) in headers) {
            val k = n.lowercase()
            val prev = m[k]
            m[k] = if (prev == null) n to v else prev.first to (prev.second + (if (k == "cookie") "; " else ", ") + v)
        }
        m.values.toList()
    }

    companion object {
        /**
         * Parses a raw HTTP/1.x request. [upstream] ("host:port") is used when there is no Host header and
         * to pick https for :443 / :8443 when the target is not an absolute URL.
         */
        fun fromRaw(raw: ByteArray, upstream: String? = null, tls: Boolean = false): SnippetRequest {
            val msg = HttpExchanges.parseStream(raw, true, emptyList()).firstOrNull()
                ?: throw IllegalArgumentException("message is not a parseable HTTP/1.x request")
            val t = msg.target
            val url = if (t.startsWith("http://") || t.startsWith("https://")) t else {
                val up = upstream.orEmpty()
                val port = up.substringAfterLast(':', "").toIntOrNull()
                val scheme = if (tls || port == 443 || port == 8443) "https" else "http"
                val host = msg.header("host") ?: up
                require(host.isNotEmpty()) { "request has no Host header and no upstream address" }
                "$scheme://$host${if (t.startsWith("/")) t else "/$t"}"
            }
            val hs = msg.headers.filter { !it.first.equals("host", true) && !it.first.equals("content-length", true) && !it.first.equals("transfer-encoding", true) }
            return SnippetRequest(msg.method, url, hs, msg.body)
        }
    }
}

interface SnippetGenerator {
    /** Stable identifier used by the control API (`target=`). */
    val id: String
    val label: String
    val language: String
    fun generate(r: SnippetRequest): String
}

object SnippetRegistry {
    val all: List<SnippetGenerator> get() = Snippets.generators
    fun get(id: String): SnippetGenerator? = all.firstOrNull { it.id.equals(id, true) }
}

// ── String literal escaping ────────────────────────────────────────────

internal object Esc {
    /** C-family double-quoted literal. [ctrl] renders a control char (code < 0x20, 0x7f, U+2028/9). */
    fun dq(s: String, ctrl: (Int) -> String, dollar: Boolean = false, hash: Boolean = false, at: Boolean = false): String {
        val sb = StringBuilder("\"")
        for (c in s) when {
            c == '\\' -> sb.append("\\\\")
            c == '"' -> sb.append("\\\"")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            c == '$' && dollar -> sb.append("\\$")
            c == '#' && hash -> sb.append("\\#")
            c == '@' && at -> sb.append("\\@")
            c.code < 0x20 || c.code == 0x7f || c.code == 0x2028 || c.code == 0x2029 -> sb.append(ctrl(c.code))
            else -> sb.append(c)
        }
        return sb.append('"').toString()
    }

    fun sq(s: String, ctrl: (Int) -> String, dollar: Boolean = false): String {
        val sb = StringBuilder("'")
        for (c in s) when {
            c == '\\' -> sb.append("\\\\")
            c == '\'' -> sb.append("\\'")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            c == '$' && dollar -> sb.append("\\$")
            c.code < 0x20 || c.code == 0x7f -> sb.append(ctrl(c.code))
            else -> sb.append(c)
        }
        return sb.append('\'').toString()
    }

    /** POSIX shell single quotes. */
    fun sh(s: String) = "'" + s.replace("'", "'\\''") + "'"
    /** PHP single quotes (only \ and ' special). */
    fun php(s: String) = "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
    /** PowerShell single quotes (only ' special, doubled). */
    fun ps(s: String) = "'" + s.replace("'", "''") + "'"

    val u4: (Int) -> String = { "\\u%04x".format(it) }
    val ubrace: (Int) -> String = { "\\u{%x}".format(it) }
    val x2: (Int) -> String = { "\\x%02x".format(it) }
    val oct3: (Int) -> String = { "\\%03o".format(it) }
}

private class Gen(
    override val id: String, override val label: String, override val language: String,
    private val fn: (SnippetRequest) -> String,
) : SnippetGenerator {
    override fun generate(r: SnippetRequest) = fn(r)
}

object Snippets {
    private fun hexBytes(b: ByteArray, prefix: String = "0x") = b.joinToString(", ") { "$prefix%02x".format(it.toInt() and 0xff) }

    // Shorthand: the "decode base64 into stdin" prefix used by shell-based generators.
    private fun b64Pipe(r: SnippetRequest) = "base64 -d <<< ${Esc.sh(r.base64)} | "

    val generators: List<SnippetGenerator> = listOf(
        Gen("curl", "cURL", "shell") { r ->
            val parts = ArrayList<String>()
            val m = r.method.uppercase()
            parts.add("curl" + when {
                m == "HEAD" -> " --head"
                m == "GET" && !r.hasBody -> ""
                else -> " -X $m"
            } + " " + Esc.sh(r.url))
            for ((n, v) in r.headers) parts.add("-H " + Esc.sh("$n: $v"))
            if (r.isBinary) parts.add("--data-binary @-") else if (r.hasBody) parts.add("--data-binary " + Esc.sh(r.bodyText!!))
            (if (r.isBinary) b64Pipe(r) else "") + parts.joinToString(" \\\n  ")
        },

        Gen("python-requests", "Python (requests)", "python") { r ->
            val sb = StringBuilder("import requests\n")
            if (r.isBinary) sb.append("import base64\n")
            sb.append("\nurl = ${py(r.url)}\n")
            sb.append("headers = ${pyHeaders(r)}\n")
            if (r.hasBody) sb.append("payload = ${pyBody(r)}\n")
            sb.append("\nresponse = requests.request(${py(r.method)}, url, headers=headers${if (r.hasBody) ", data=payload" else ""})\n")
            sb.append("print(response.text)")
            sb.toString()
        },

        Gen("python-http-client", "Python (http.client)", "python") { r ->
            val cls = if (r.isHttps) "HTTPSConnection" else "HTTPConnection"
            val sb = StringBuilder("import http.client\n")
            if (r.isBinary) sb.append("import base64\n")
            sb.append("\nconn = http.client.$cls(${py(r.hostname)}${r.port?.let { ", $it" } ?: ""})\n")
            if (r.hasBody) sb.append("payload = ${pyBody(r)}\n")
            sb.append("headers = ${pyHeaders(r)}\n")
            sb.append("conn.request(${py(r.method)}, ${py(r.target)}, ${if (r.hasBody) "payload, headers" else "headers=headers"})\n")
            sb.append("res = conn.getresponse()\nprint(res.read().decode(\"utf-8\"))")
            sb.toString()
        },

        Gen("javascript-fetch", "JavaScript (fetch)", "javascript") { r ->
            val sb = StringBuilder("const response = await fetch(${js(r.url)}, {\n  method: ${js(r.method)},\n")
            if (r.headers.isNotEmpty()) sb.append("  headers: ${jsHeaders(r, 2)},\n")
            if (r.isBinary) sb.append("  body: Uint8Array.from(atob(${js(r.base64)}), (c) => c.charCodeAt(0)),\n")
            else if (r.hasBody) sb.append("  body: ${js(r.bodyText!!)},\n")
            sb.append("});\nconsole.log(await response.text());")
            sb.toString()
        },

        Gen("node-axios", "Node.js (axios)", "javascript") { r ->
            val sb = StringBuilder("const axios = require(\"axios\");\n\naxios({\n  method: ${js(r.method.lowercase())},\n  url: ${js(r.url)},\n")
            if (r.headers.isNotEmpty()) sb.append("  headers: ${jsHeaders(r, 2)},\n")
            if (r.isBinary) sb.append("  data: Buffer.from(${js(r.base64)}, \"base64\"),\n")
            else if (r.hasBody) sb.append("  data: ${js(r.bodyText!!)},\n")
            sb.append("  responseType: \"text\",\n  transformResponse: (d) => d,\n})\n  .then((res) => console.log(res.data))\n  .catch((err) => console.error(err));")
            sb.toString()
        },

        Gen("node-http", "Node.js (http)", "javascript") { r ->
            val sb = StringBuilder("const http = require(${js(if (r.isHttps) "https" else "http")});\n\nconst options = {\n")
            sb.append("  method: ${js(r.method)},\n  hostname: ${js(r.hostname)},\n")
            r.port?.let { sb.append("  port: $it,\n") }
            sb.append("  path: ${js(r.target)},\n")
            if (r.headers.isNotEmpty()) sb.append("  headers: ${jsHeaders(r, 2)},\n")
            sb.append("};\n\nconst req = http.request(options, (res) => {\n  const chunks = [];\n")
            sb.append("  res.on(\"data\", (chunk) => chunks.push(chunk));\n")
            sb.append("  res.on(\"end\", () => console.log(Buffer.concat(chunks).toString()));\n});\n\n")
            sb.append("req.on(\"error\", (e) => console.error(e));\n")
            if (r.isBinary) sb.append("req.write(Buffer.from(${js(r.base64)}, \"base64\"));\n")
            else if (r.hasBody) sb.append("req.write(${js(r.bodyText!!)});\n")
            sb.append("req.end();")
            sb.toString()
        },

        Gen("java-httpclient", "Java (HttpClient 11+)", "java") { r ->
            val restricted = setOf("host", "content-length", "connection", "upgrade", "expect")
            val sb = StringBuilder()
            sb.append("import java.net.URI;\nimport java.net.http.HttpClient;\nimport java.net.http.HttpRequest;\nimport java.net.http.HttpResponse;\n\n")
            sb.append("public class Main {\n    public static void main(String[] args) throws Exception {\n")
            sb.append("        HttpClient client = HttpClient.newHttpClient();\n")
            sb.append("        HttpRequest request = HttpRequest.newBuilder()\n            .uri(URI.create(${java(r.url)}))\n")
            for ((n, v) in r.headers) if (n.lowercase() !in restricted) sb.append("            .header(${java(n)}, ${java(v)})\n")
            val pub = when {
                r.isBinary -> "HttpRequest.BodyPublishers.ofByteArray(java.util.Base64.getDecoder().decode(${java(r.base64)}))"
                r.hasBody -> "HttpRequest.BodyPublishers.ofString(${java(r.bodyText!!)})"
                else -> "HttpRequest.BodyPublishers.noBody()"
            }
            sb.append("            .method(${java(r.method)}, $pub)\n            .build();\n")
            sb.append("        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());\n")
            sb.append("        System.out.println(response.body());\n    }\n}")
            sb.toString()
        },

        Gen("kotlin-okhttp", "Kotlin (OkHttp)", "kotlin") { r ->
            val ct = r.header("content-type")
            val mt = if (ct != null) "${kt(ct)}.toMediaType()" else "null"
            val body = when {
                r.isBinary -> "java.util.Base64.getDecoder().decode(${kt(r.base64)}).toRequestBody($mt)"
                r.hasBody -> "${kt(r.bodyText!!)}.toRequestBody($mt)"
                r.method.uppercase() in setOf("POST", "PUT", "PATCH", "PROPPATCH", "REPORT") -> "ByteArray(0).toRequestBody(null)"
                else -> "null"
            }
            val sb = StringBuilder("import okhttp3.MediaType.Companion.toMediaType\nimport okhttp3.OkHttpClient\nimport okhttp3.Request\nimport okhttp3.RequestBody.Companion.toRequestBody\n\n")
            sb.append("fun main() {\n    val client = OkHttpClient()\n    val request = Request.Builder()\n        .url(${kt(r.url)})\n        .method(${kt(r.method)}, $body)\n")
            for ((n, v) in r.headers) if (!(n.equals("content-type", true) && r.hasBody)) sb.append("        .addHeader(${kt(n)}, ${kt(v)})\n")
            sb.append("        .build()\n    client.newCall(request).execute().use { response ->\n        println(response.body?.string())\n    }\n}")
            sb.toString()
        },

        Gen("go-nethttp", "Go (net/http)", "go") { r ->
            val imports = mutableListOf("\"fmt\"", "\"io\"", "\"net/http\"")
            if (r.isBinary) { imports.add("\"bytes\""); imports.add("\"encoding/base64\"") } else if (r.hasBody) imports.add("\"strings\"")
            imports.sort()
            val sb = StringBuilder("package main\n\nimport (\n")
            for (i in imports) sb.append("\t$i\n")
            sb.append(")\n\nfunc main() {\n")
            val bodyArg = when {
                r.isBinary -> { sb.append("\tpayload, _ := base64.StdEncoding.DecodeString(${go(r.base64)})\n"); "bytes.NewReader(payload)" }
                r.hasBody -> { sb.append("\tpayload := strings.NewReader(${go(r.bodyText!!)})\n"); "payload" }
                else -> "nil"
            }
            sb.append("\treq, err := http.NewRequest(${go(r.method)}, ${go(r.url)}, $bodyArg)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n")
            for ((n, v) in r.headers) sb.append("\treq.Header.Add(${go(n)}, ${go(v)})\n")
            sb.append("\tresp, err := http.DefaultClient.Do(req)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n\tdefer resp.Body.Close()\n")
            sb.append("\tdata, _ := io.ReadAll(resp.Body)\n\tfmt.Println(string(data))\n}")
            sb.toString()
        },

        Gen("php-curl", "PHP (cURL)", "php") { r ->
            val sb = StringBuilder("<?php\n\$ch = curl_init();\ncurl_setopt_array(\$ch, [\n")
            sb.append("    CURLOPT_URL => ${Esc.php(r.url)},\n    CURLOPT_RETURNTRANSFER => true,\n    CURLOPT_CUSTOMREQUEST => ${Esc.php(r.method)},\n")
            if (r.isBinary) sb.append("    CURLOPT_POSTFIELDS => base64_decode(${Esc.php(r.base64)}),\n")
            else if (r.hasBody) sb.append("    CURLOPT_POSTFIELDS => ${Esc.php(r.bodyText!!)},\n")
            if (r.method.equals("HEAD", true)) sb.append("    CURLOPT_NOBODY => true,\n")
            if (r.headers.isNotEmpty()) {
                sb.append("    CURLOPT_HTTPHEADER => [\n")
                for ((n, v) in r.headers) sb.append("        ${Esc.php("$n: $v")},\n")
                sb.append("    ],\n")
            }
            sb.append("]);\n\$response = curl_exec(\$ch);\nif (\$response === false) {\n    echo curl_error(\$ch);\n}\ncurl_close(\$ch);\necho \$response;")
            sb.toString()
        },

        Gen("ruby-nethttp", "Ruby (Net::HTTP)", "ruby") { r ->
            val known = setOf("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE")
            val m = r.method.uppercase()
            val sb = StringBuilder("require \"net/http\"\nrequire \"uri\"\n\nuri = URI.parse(${rb(r.url)})\nhttp = Net::HTTP.new(uri.host, uri.port)\n")
            if (r.isHttps) sb.append("http.use_ssl = true\n")
            if (m in known) sb.append("request = Net::HTTP::${m.lowercase().replaceFirstChar { it.uppercase() }}.new(uri.request_uri)\n")
            else sb.append("request = Net::HTTPGenericRequest.new(${rb(m)}, ${r.hasBody}, true, uri.request_uri)\n")
            for ((n, v) in r.mergedHeaders) sb.append("request[${rb(n)}] = ${rb(v)}\n")
            if (r.isBinary) sb.append("request.body = ${rb(r.base64)}.unpack1(\"m\")\n")
            else if (r.hasBody) sb.append("request.body = ${rb(r.bodyText!!)}\n")
            sb.append("response = http.request(request)\nputs response.body")
            sb.toString()
        },

        Gen("csharp-httpclient", "C# (HttpClient)", "csharp") { r ->
            val sb = StringBuilder("using System;\nusing System.Net.Http;\nusing System.Threading.Tasks;\n\nclass Program\n{\n    static async Task Main()\n    {\n")
            sb.append("        using var client = new HttpClient();\n")
            sb.append("        var request = new HttpRequestMessage(new HttpMethod(${cs(r.method)}), ${cs(r.url)});\n")
            val contentHeaders = r.headers.filter { it.first.lowercase().startsWith("content-") || it.first.lowercase() in setOf("expires", "last-modified", "allow") }
            for ((n, v) in r.headers) if ((n to v) !in contentHeaders) sb.append("        request.Headers.TryAddWithoutValidation(${cs(n)}, ${cs(v)});\n")
            if (r.hasBody) {
                if (r.isBinary) sb.append("        request.Content = new ByteArrayContent(Convert.FromBase64String(${cs(r.base64)}));\n")
                else sb.append("        request.Content = new StringContent(${cs(r.bodyText!!)});\n")
                sb.append("        request.Content.Headers.Clear();\n")
                for ((n, v) in contentHeaders) sb.append("        request.Content.Headers.TryAddWithoutValidation(${cs(n)}, ${cs(v)});\n")
            }
            sb.append("        var response = await client.SendAsync(request);\n        Console.WriteLine(await response.Content.ReadAsStringAsync());\n    }\n}")
            sb.toString()
        },

        Gen("powershell", "PowerShell (Invoke-WebRequest)", "powershell") { r ->
            val sb = StringBuilder()
            val ct = r.header("content-type")
            val ua = r.header("user-agent")
            val hs = r.mergedHeaders.filter { !it.first.equals("content-type", true) && !it.first.equals("user-agent", true) }
            if (hs.isNotEmpty()) {
                sb.append("\$headers = @{\n")
                for ((n, v) in hs) sb.append("    ${Esc.ps(n)} = ${Esc.ps(v)}\n")
                sb.append("}\n")
            }
            if (r.isBinary) sb.append("\$body = [Convert]::FromBase64String(${Esc.ps(r.base64)})\n")
            else if (r.hasBody) sb.append("\$body = ${Esc.ps(r.bodyText!!)}\n")
            sb.append("\$response = Invoke-WebRequest -Uri ${Esc.ps(r.url)} -Method ${r.method.uppercase()}")
            if (hs.isNotEmpty()) sb.append(" -Headers \$headers")
            if (ct != null) sb.append(" -ContentType ${Esc.ps(ct)}")
            if (ua != null) sb.append(" -UserAgent ${Esc.ps(ua)}")
            if (r.hasBody) sb.append(" -Body \$body")
            sb.append("\n\$response.Content")
            sb.toString()
        },

        Gen("httpie", "HTTPie", "shell") { r ->
            val parts = ArrayList<String>()
            parts.add("http ${r.method.uppercase()} ${Esc.sh(r.url)}")
            for ((n, v) in r.headers) parts.add(Esc.sh(if (v.isEmpty()) "$n;" else "$n:$v"))
            if (r.hasBody && !r.isBinary) parts.add("--raw " + Esc.sh(r.bodyText!!))
            (if (r.isBinary) b64Pipe(r) else "") + parts.joinToString(" \\\n  ")
        },

        Gen("wget", "Wget", "shell") { r ->
            val parts = ArrayList<String>()
            parts.add("wget --quiet")
            parts.add("--method ${Esc.sh(r.method.uppercase())}")
            for ((n, v) in r.headers) parts.add("--header " + Esc.sh("$n: $v"))
            if (r.isBinary) parts.add("--body-file=/dev/stdin") else if (r.hasBody) parts.add("--body-data " + Esc.sh(r.bodyText!!))
            parts.add("-O -")
            parts.add(Esc.sh(r.url))
            (if (r.isBinary) b64Pipe(r) else "") + parts.joinToString(" \\\n  ")
        },

        Gen("rust-reqwest", "Rust (reqwest)", "rust") { r ->
            val m = r.method.uppercase()
            val method = if (m in setOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT")) "reqwest::Method::$m"
                         else "reqwest::Method::from_bytes(b${rs(m)})?"
            val sb = StringBuilder("#[tokio::main]\nasync fn main() -> Result<(), Box<dyn std::error::Error>> {\n    let client = reqwest::Client::new();\n")
            sb.append("    let response = client\n        .request($method, ${rs(r.url)})\n")
            for ((n, v) in r.headers) sb.append("        .header(${rs(n)}, ${rs(v)})\n")
            if (r.isBinary) sb.append("        .body(vec![${hexBytes(r.body)}])\n")
            else if (r.hasBody) sb.append("        .body(${rs(r.bodyText!!)})\n")
            sb.append("        .send()\n        .await?;\n    println!(\"{}\", response.text().await?);\n    Ok(())\n}")
            sb.toString()
        },

        Gen("swift-urlsession", "Swift (URLSession)", "swift") { r ->
            val sb = StringBuilder("import Foundation\n\nvar request = URLRequest(url: URL(string: ${sw(r.url)})!)\nrequest.httpMethod = ${sw(r.method)}\n")
            for ((n, v) in r.headers) sb.append("request.addValue(${sw(v)}, forHTTPHeaderField: ${sw(n)})\n")
            if (r.isBinary) sb.append("request.httpBody = Data(base64Encoded: ${sw(r.base64)})\n")
            else if (r.hasBody) sb.append("request.httpBody = ${sw(r.bodyText!!)}.data(using: .utf8)\n")
            sb.append("\nlet semaphore = DispatchSemaphore(value: 0)\n")
            sb.append("let task = URLSession.shared.dataTask(with: request) { data, response, error in\n")
            sb.append("    if let error = error {\n        print(error)\n    } else if let data = data, let text = String(data: data, encoding: .utf8) {\n        print(text)\n    }\n    semaphore.signal()\n}\n")
            sb.append("task.resume()\nsemaphore.wait()")
            sb.toString()
        },

        Gen("dart-http", "Dart (http)", "dart") { r ->
            val sb = StringBuilder()
            if (r.isBinary) sb.append("import 'dart:convert';\n")
            sb.append("import 'package:http/http.dart' as http;\n\nFuture<void> main() async {\n")
            sb.append("  final request = http.Request(${dt(r.method)}, Uri.parse(${dt(r.url)}));\n")
            if (r.headers.isNotEmpty()) {
                sb.append("  request.headers.addAll({\n")
                for ((n, v) in r.mergedHeaders) sb.append("    ${dt(n)}: ${dt(v)},\n")
                sb.append("  });\n")
            }
            if (r.isBinary) sb.append("  request.bodyBytes = base64Decode(${dt(r.base64)});\n")
            else if (r.hasBody) sb.append("  request.body = ${dt(r.bodyText!!)};\n")
            sb.append("  final response = await http.Response.fromStream(await request.send());\n  print(response.body);\n}")
            sb.toString()
        },

        Gen("r-httr", "R (httr)", "r") { r ->
            val args = ArrayList<String>()
            args.add("  ${rq(r.method.uppercase())}")
            args.add("  ${rq(r.url)}")
            if (r.headers.isNotEmpty()) {
                args.add("  add_headers(\n" + r.mergedHeaders.joinToString(",\n") { "    ${rq(it.first)} = ${rq(it.second)}" } + "\n  )")
            }
            if (r.isBinary) { args.add("  body = as.raw(c(${hexBytes(r.body)}))"); args.add("  encode = \"raw\"") }
            else if (r.hasBody) { args.add("  body = ${rq(r.bodyText!!)}"); args.add("  encode = \"raw\"") }
            "library(httr)\n\nresponse <- VERB(\n" + args.joinToString(",\n") + "\n)\ncat(content(response, \"text\", encoding = \"UTF-8\"))"
        },

        Gen("objc-nsurlsession", "Objective-C (NSURLSession)", "objectivec") { r ->
            val sb = StringBuilder("#import <Foundation/Foundation.h>\n\nint main(int argc, const char * argv[]) {\n    @autoreleasepool {\n")
            sb.append("        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:${oc(r.url)}]];\n")
            sb.append("        [request setHTTPMethod:${oc(r.method)}];\n")
            for ((n, v) in r.headers) sb.append("        [request addValue:${oc(v)} forHTTPHeaderField:${oc(n)}];\n")
            if (r.isBinary) sb.append("        [request setHTTPBody:[[NSData alloc] initWithBase64EncodedString:${oc(r.base64)} options:0]];\n")
            else if (r.hasBody) sb.append("        [request setHTTPBody:[${oc(r.bodyText!!)} dataUsingEncoding:NSUTF8StringEncoding]];\n")
            sb.append("\n        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);\n")
            sb.append("        NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {\n")
            sb.append("            if (error) {\n                NSLog(@\"%@\", error);\n            } else {\n                NSLog(@\"%@\", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);\n            }\n")
            sb.append("            dispatch_semaphore_signal(semaphore);\n        }];\n        [task resume];\n        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);\n    }\n    return 0;\n}")
            sb.toString()
        },
    )

    // Per-language literal helpers
    private fun py(s: String) = Esc.dq(s, Esc.x2)
    private fun js(s: String) = Esc.dq(s, Esc.u4)
    private fun java(s: String) = Esc.dq(s, Esc.oct3)
    private fun kt(s: String) = Esc.dq(s, Esc.u4, dollar = true)
    private fun go(s: String) = Esc.dq(s, Esc.u4)
    private fun rb(s: String) = Esc.dq(s, Esc.x2, hash = true)
    private fun cs(s: String) = Esc.dq(s, Esc.u4)
    private fun rs(s: String) = Esc.dq(s, Esc.ubrace)
    private fun sw(s: String) = Esc.dq(s, Esc.ubrace)
    private fun rq(s: String) = Esc.dq(s, Esc.u4)
    private fun oc(s: String) = "@" + Esc.dq(s, Esc.oct3)
    private fun dt(s: String) = Esc.sq(s, Esc.ubrace, dollar = true)

    private fun pyBody(r: SnippetRequest): String =
        if (r.isBinary) "base64.b64decode(${py(r.base64)})"
        else py(r.bodyText!!) + if (r.bodyText!!.any { it.code > 0x7f }) ".encode(\"utf-8\")" else ""

    private fun pyHeaders(r: SnippetRequest): String =
        if (r.headers.isEmpty()) "{}" else "{\n" + r.mergedHeaders.joinToString("") { "    ${py(it.first)}: ${py(it.second)},\n" } + "}"

    private fun jsHeaders(r: SnippetRequest, indent: Int): String =
        ("{\n" + r.mergedHeaders.joinToString("") { "  ${js(it.first)}: ${js(it.second)},\n" } + "}").let {
            // first line stays on the caller's line; the rest is indented
            val ls = it.lines()
            ls.first() + "\n" + ls.drop(1).joinToString("\n") { l -> " ".repeat(indent) + l }
        }
}
