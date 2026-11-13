package expedition.tls

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Date

/**
 * A locally-generated default CA, so TLS MITM / STARTTLS work out of the box without the
 * user first exporting Burp's CA. A UNIQUE CA is minted per machine and persisted under
 * [dir] — never bundled in the repo (a shared/committed CA private key would let anyone
 * trusting it be MITM'd). The matching PEM cert is written alongside so it can be installed
 * into clients that don't already trust Burp's CA.
 */
object DefaultCa {

    private const val CA_FILE = "expedition-ca.p12"
    private const val CRT_FILE = "expedition-ca.crt"
    private const val ALIAS = "expedition-ca"
    private const val PASS_FILE = "expedition-ca.pass"

    /** Password used by CAs created before per-machine passwords existed. Kept as a fallback only. */
    const val LEGACY_PASSWORD = "expedition"

    /**
     * Picks the keystore password for the CA under [dir]:
     *  1. [envPassword] (EXPEDITION_CA_PASSWORD) when set,
     *  2. otherwise the random password stored in `expedition-ca.pass` (created on first use, mode 600),
     *  3. otherwise [LEGACY_PASSWORD] for a CA that predates this scheme.
     * When a keystore already exists, the first candidate that actually opens it wins, so an
     * existing CA stays usable after the env var changes or the legacy password is in use.
     */
    fun resolvePassword(dir: File, envPassword: String?): CharArray {
        dir.mkdirs()
        val p12 = File(dir, CA_FILE)
        val passFile = File(dir, PASS_FILE)
        val env = envPassword?.takeIf { it.isNotEmpty() }
        val stored = passFile.takeIf { it.exists() }?.readText()?.trim()?.takeIf { it.isNotEmpty() }

        if (!p12.exists()) {
            // Fresh CA: explicit env wins; else reuse or mint a random per-machine password.
            env?.let { return it.toCharArray() }
            stored?.let { return it.toCharArray() }
            val generated = randomPassword()
            writeOwnerOnly(passFile, generated)
            return generated.toCharArray()
        }
        val candidates = listOfNotNull(env, stored, LEGACY_PASSWORD).distinct()
        val opened = candidates.firstOrNull { canOpen(p12, it.toCharArray()) }
        return (opened ?: env ?: stored ?: LEGACY_PASSWORD).toCharArray()
    }

    private fun canOpen(p12: File, password: CharArray): Boolean = runCatching {
        p12.inputStream().use { KeyStore.getInstance("PKCS12").load(it, password) }
    }.isSuccess

    private fun randomPassword(): String {
        val bytes = ByteArray(24).also { java.security.SecureRandom().nextBytes(it) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /** Creates [f] with owner-only permissions (0600 on POSIX) before writing the secret into it. */
    private fun writeOwnerOnly(f: File, content: String) {
        f.createNewFile()
        restrictToOwner(f)
        f.writeText(content)
    }

    /** Returns the CA keystore under [dir], generating (and persisting) it once if absent. */
    fun ensureDefaultCa(dir: File, password: CharArray): File {
        dir.mkdirs()
        val p12 = File(dir, CA_FILE)
        if (p12.exists()) return p12

        Security.addProvider(BouncyCastleProvider())
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = Instant.now()
        val subject = X500Name("CN=Expedition Auto CA")
        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
            subject, keyPair.public
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        // Subject Key Identifier so issued leaves' Authority Key Identifier matches (OpenSSL 3.x).
        builder.addExtension(
            Extension.subjectKeyIdentifier, false,
            org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.public)
        )
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        )

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, password)
        ks.setKeyEntry(ALIAS, keyPair.private, password, arrayOf(cert))
        // Write to a temp file, restrict perms before the key bytes land, then atomically rename —
        // so a crash mid-write never leaves a half-written keystore that later loads treat as valid.
        // Unique temp name (avoids a concurrent-first-run collision) + cleanup on any failure.
        val tmp = File.createTempFile("expedition-ca", ".p12.tmp", dir)
        try {
            restrictToOwner(tmp)   // the keystore holds a CA private key — not world-readable
            tmp.outputStream().use { ks.store(it, password) }
            try {
                java.nio.file.Files.move(tmp.toPath(), p12.toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE)
            } catch (e: java.nio.file.AtomicMoveNotSupportedException) {
                java.nio.file.Files.move(tmp.toPath(), p12.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            tmp.delete()   // no-op once the move consumed it; removes the temp on a failed write
        }

        // Export the cert (PEM) for installing into clients that don't trust Burp's CA.
        val pem = "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded) +
            "\n-----END CERTIFICATE-----\n"
        File(dir, CRT_FILE).writeText(pem)
        return p12
    }

    /** Restrict a private-key file to the owner. POSIX (Linux/macOS) → 0600; no-op-safe on Windows. */
    private fun restrictToOwner(f: File) {
        f.setReadable(false, false); f.setReadable(true, true)
        f.setWritable(false, false); f.setWritable(true, true)
        f.setExecutable(false, false)
    }
}
