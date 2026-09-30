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
        val tmp = File(dir, "$CA_FILE.tmp")
        tmp.createNewFile()
        restrictToOwner(tmp)   // the keystore holds a CA private key — not world-readable
        tmp.outputStream().use { ks.store(it, password) }
        try {
            java.nio.file.Files.move(tmp.toPath(), p12.toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.AtomicMoveNotSupportedException) {
            java.nio.file.Files.move(tmp.toPath(), p12.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
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
