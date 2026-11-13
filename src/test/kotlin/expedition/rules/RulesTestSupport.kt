package expedition.rules

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** A request as seen by [FakeHttpServer] (independent parser: does not use the code under test). */
class SeenRequest(val method: String, val target: String, val headers: Map<String, String>, val body: String) {
    override fun toString() = "$method $target"
}

/** One parsed message read by the test client / server helpers. */
class WireMsg(val startLine: String, val headers: Map<String, String>, val body: String) {
    val status: Int get() = startLine.split(' ')[1].toInt()
    fun header(n: String) = headers[n.lowercase()]
}

object Wire {
    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return sb.toString().removeSuffix("\r")
            sb.append(c.toChar())
        }
    }

    private fun readN(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = input.read(out, got, n - got)
            if (r < 0) throw java.io.EOFException("eof after $got/$n")
            got += r
        }
        return out
    }

    /** Reads one message; [noBody] for HEAD responses. Returns null on clean EOF before a start line. */
    fun read(input: InputStream, noBody: Boolean = false): WireMsg? {
        var start = readLine(input) ?: return null
        while (start.isEmpty()) start = readLine(input) ?: return null
        val headers = LinkedHashMap<String, String>()
        while (true) {
            val l = readLine(input) ?: throw java.io.EOFException("eof in headers")
            if (l.isEmpty()) break
            headers[l.substringBefore(':').trim().lowercase()] = l.substringAfter(':').trim()
        }
        val status = if (start.startsWith("HTTP/")) start.split(' ')[1].toInt() else 0
        val body = ByteArrayOutputStream()
        when {
            noBody || status == 101 || status == 204 || status == 304 || status in 100..199 -> {}
            headers["transfer-encoding"]?.contains("chunked") == true -> {
                while (true) {
                    val size = readLine(input)!!.substringBefore(';').trim().toInt(16)
                    if (size == 0) { while (readLine(input)!!.isNotEmpty()) {}; break }
                    body.write(readN(input, size)); readLine(input)
                }
            }
            headers["content-length"] != null -> body.write(readN(input, headers["content-length"]!!.toInt()))
            status != 0 -> body.write(input.readBytes())
        }
        return WireMsg(start, headers, body.toString(Charsets.ISO_8859_1))
    }
}

/**
 * Keep-alive HTTP/1.1 upstream. Answers `200` with body `"<name>:<METHOD> <target> body=<body>"`,
 * echoes request headers as `X-Echo-<name>`, `/chunked` answers chunked, an `Upgrade` request
 * gets `101` and the connection becomes a raw echo.
 */
class FakeHttpServer(val name: String = "up") : AutoCloseable {
    private val server = ServerSocket(0)
    val port: Int get() = server.localPort
    val requests = CopyOnWriteArrayList<SeenRequest>()
    val accepted = AtomicInteger()
    val bytesReceived = AtomicLong()

    private val thread = Thread {
        while (true) {
            val s = try { server.accept() } catch (_: Exception) { break }
            accepted.incrementAndGet()
            Thread { runCatching { serve(s) }; runCatching { s.close() } }.apply { isDaemon = true }.start()
        }
    }.apply { isDaemon = true; start() }

    private class Counting(val inner: InputStream, val n: AtomicLong) : InputStream() {
        override fun read(): Int = inner.read().also { if (it >= 0) n.incrementAndGet() }
        override fun read(b: ByteArray, off: Int, len: Int): Int = inner.read(b, off, len).also { if (it > 0) n.addAndGet(it.toLong()) }
    }

    private fun serve(s: Socket) {
        val input = Counting(s.getInputStream(), bytesReceived)
        val out = s.getOutputStream()
        while (true) {
            val m = Wire.read(input) ?: return
            val parts = m.startLine.split(' ')
            val req = SeenRequest(parts[0], parts[1], m.headers, m.body)
            requests += req
            if (m.header("upgrade") != null) {
                out.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: ${m.header("upgrade")}\r\nConnection: Upgrade\r\n\r\n".toByteArray())
                out.flush()
                val buf = ByteArray(4096)
                while (true) { val n = input.read(buf); if (n < 0) return; out.write(buf, 0, n); out.flush() }
            }
            val body = "$name:${req.method} ${req.target} body=${req.body}".toByteArray(Charsets.ISO_8859_1)
            val echo = m.headers.entries.joinToString("") { "X-Echo-${it.key}: ${it.value}\r\n" }
            val head = "HTTP/1.1 200 OK\r\nX-Upstream: $name\r\n$echo"
            if (req.target.startsWith("/chunked")) {
                out.write("${head}Transfer-Encoding: chunked\r\n\r\n".toByteArray())
                body.toList().chunked(4).forEach { c ->
                    out.write("${Integer.toHexString(c.size)}\r\n".toByteArray()); out.write(c.toByteArray()); out.write("\r\n".toByteArray())
                }
                out.write("0\r\n\r\n".toByteArray())
            } else {
                out.write("${head}Content-Length: ${if (req.method == "HEAD") 0 else body.size}\r\n\r\n".toByteArray())
                if (req.method != "HEAD") out.write(body)
            }
            out.flush()
        }
    }

    override fun close() { runCatching { server.close() } }
}

/** Shared sandbox for `bodyFile` in tests (`-Dexpedition.rulesFilesDir`), set once per JVM. */
object RulesTestFiles {
    val dir: java.io.File by lazy {
        val d = java.nio.file.Files.createTempDirectory("expedition-rules-files").toFile().canonicalFile
        d.deleteOnExit()
        System.setProperty("expedition.rulesFilesDir", d.path)
        d
    }

    fun file(name: String, content: ByteArray): java.io.File = java.io.File(dir, name).also { it.writeBytes(content) }
}
