package expedition.setup

import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/** Everything a generator needs. Pure data: generators never touch the filesystem except through [runner]/[state]. */
data class SetupContext(
    val host: String = "127.0.0.1",
    val port: Int = 8080,
    /** PEM certificate of the Expedition CA (~/.expedition/expedition-ca.crt by default). */
    val caCert: File,
    /** "socks5" (Expedition's dynamic listener) or "http" (e.g. a chained HTTP proxy). */
    val proxyType: String = "socks5",
    val params: Map<String, String> = emptyMap(),
    val runner: CommandRunner = ProcessRunner(),
    val state: SetupState = SetupState(),
    /** Scratch dir for generated artifacts (frida scripts, truststores, browser profiles). */
    val workDir: File = File(caCert.absoluteFile.parentFile, "setup"),
) {
    fun param(name: String, default: String = ""): String = params[name]?.takeIf { it.isNotBlank() } ?: default
    val proxyAddr: String get() = "$host:$port"
    /** URL form for env vars / flags. socks5h = resolve DNS through the proxy. */
    val proxyUrl: String get() = if (proxyType == "http") "http://$host:$port" else "socks5h://$host:$port"
    val caPath: String get() = caCert.absolutePath
}

data class ParamSpec(val name: String, val label: String, val default: String = "", val options: List<String> = emptyList())

data class ActionResult(val ok: Boolean, val log: String)

/** Handles of processes started by Apply (frida, browsers), so Undo can stop them. */
class SetupState {
    val processes = ConcurrentHashMap<String, Process>()
    fun stop(key: String): Boolean = processes.remove(key)?.also { it.destroy() } != null
}

interface SetupTarget {
    val id: String
    val title: String
    val params: List<ParamSpec> get() = emptyList()
    /** True when [apply] actually runs something (UI shows Apply/Undo). */
    val executable: Boolean get() = false
    /** Pure: instructions / commands as text. */
    fun guide(ctx: SetupContext): String
    fun apply(ctx: SetupContext): ActionResult = ActionResult(false, "$id has no apply action")
    fun undo(ctx: SetupContext): ActionResult = ActionResult(false, "$id has no undo action")
}

data class CmdResult(val exit: Int, val output: String, val missing: Boolean = false, val timedOut: Boolean = false) {
    val ok: Boolean get() = exit == 0 && !missing && !timedOut
}

interface CommandRunner {
    /** Runs an argv (never a shell string) and waits up to [timeoutMs]. */
    fun run(args: List<String>, timeoutMs: Long = 15_000): CmdResult
    /** Starts a long-running argv; throws IOException if the tool is missing. */
    fun spawn(args: List<String>): Process
}

class ProcessRunner : CommandRunner {
    override fun run(args: List<String>, timeoutMs: Long): CmdResult {
        val p = try {
            ProcessBuilder(args).redirectErrorStream(true).start()
        } catch (e: IOException) {
            return CmdResult(-1, "'${args.firstOrNull()}' not found or not executable (is it in PATH?)", missing = true)
        }
        p.outputStream.close()
        val sb = StringBuilder()
        val reader = Thread {
            runCatching { p.inputStream.bufferedReader().forEachLine { if (sb.length < 64_000) sb.appendLine(it) } }
        }.apply { isDaemon = true; start() }
        if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            p.destroyForcibly(); reader.join(500)
            return CmdResult(-1, sb.toString() + "timed out after ${timeoutMs}ms", timedOut = true)
        }
        reader.join(1000)
        return CmdResult(p.exitValue(), sb.toString())
    }

    override fun spawn(args: List<String>): Process =
        ProcessBuilder(args).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start()
}

object Sh {
    /** POSIX single-quote. */
    fun q(s: String): String =
        if (s.isNotEmpty() && s.all { it.isLetterOrDigit() || it in "_-./:=@%+," }) s else "'" + s.replace("'", "'\\''") + "'"
    /** PowerShell single-quote. */
    fun ps(s: String): String = "'" + s.replace("'", "''") + "'"
    /** cmd.exe double-quote (good enough for paths/URLs). */
    fun cmd(s: String): String = "\"" + s.replace("\"", "\"\"") + "\""
    fun join(args: List<String>): String = args.joinToString(" ") { q(it) }
}

object CaInfo {
    fun load(f: File): X509Certificate? = runCatching {
        f.inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate }
    }.getOrNull()

    /** Base64(SHA-256(SubjectPublicKeyInfo)) — the format of Chromium's --ignore-certificate-errors-spki-list. */
    fun spkiHash(cert: X509Certificate): String =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

    fun spkiHash(f: File): String? = load(f)?.let { spkiHash(it) }
}
