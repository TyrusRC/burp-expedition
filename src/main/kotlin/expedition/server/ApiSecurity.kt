package expedition.server

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.SecureRandom

/**
 * Confines file paths received over the control API to one base directory (by default
 * `~/.expedition`). Relative paths resolve against the base; the result is canonicalised
 * (symlinks resolved, `..` collapsed) and must stay inside the canonical base, so neither
 * `../` nor a symlink planted inside the base can reach outside it.
 */
class PathSandbox(base: File) {
    val base: File = base.absoluteFile

    /** The canonical file for [path], or IllegalArgumentException when it escapes the base. */
    fun resolve(path: String): File {
        require(path.isNotBlank()) { "path required" }
        require(path.none { it == '\u0000' || it.isISOControl() }) { "path contains control characters" }
        val raw = File(path).let { if (it.isAbsolute) it else File(base, path) }
        val root = base.canonicalFile
        val canon = raw.canonicalFile
        require(canon.path == root.path || canon.path.startsWith(root.path + File.separator)) {
            "path must be inside ${root.path}"
        }
        return canon
    }

    companion object {
        /** `$EXPEDITION_CA_DIR` or `~/.expedition` — the directory the API may read/write. */
        fun defaultBase(): File = File(
            System.getenv("EXPEDITION_CA_DIR")?.takeIf { it.isNotBlank() }
                ?: (System.getProperty("user.home") + File.separator + ".expedition"))
    }
}

/** Where the control-API bearer token came from. */
data class ResolvedToken(val token: String, val explicit: Boolean, val file: File?)

object ApiToken {
    const val FILE_NAME = "api-token"

    fun generate(): String {
        val b = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return b.joinToString("") { "%02x".format(it) }
    }

    /**
     * [envToken] (EXPEDITION_API_TOKEN) wins and is "explicit". Otherwise the token stored in
     * `<dir>/api-token` is reused, or a fresh random one is written there owner-only (0600),
     * so the operator / MCP client can read it but other local users cannot.
     */
    fun resolve(envToken: String?, dir: File): ResolvedToken {
        envToken?.trim()?.takeIf { it.isNotEmpty() }?.let { return ResolvedToken(it, true, null) }
        val f = File(dir, FILE_NAME)
        val existing = runCatching { f.readText().trim() }.getOrNull()
        if (!existing.isNullOrEmpty() && existing.length >= 32) { ownerOnly(f); return ResolvedToken(existing, false, f) }
        dir.mkdirs()
        val t = generate()
        // Create empty, restrict, then write — the secret is never world-readable even briefly.
        f.delete(); f.createNewFile(); ownerOnly(f)
        f.writeText(t + "\n")
        return ResolvedToken(t, false, f)
    }

    private fun ownerOnly(f: File) {
        runCatching {
            Files.setPosixFilePermissions(f.toPath(), setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
        }.onFailure {
            // Non-POSIX (Windows): best effort via the File API.
            f.setReadable(false, false); f.setReadable(true, true)
            f.setWritable(false, false); f.setWritable(true, true)
        }
    }
}
