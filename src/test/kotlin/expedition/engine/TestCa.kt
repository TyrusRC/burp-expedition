package expedition.engine

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

/** Throwaway PKCS#12 keystores for TLS tests: a CA ([ca] = true) or a self-signed server leaf. */
object TestCa {
    val password: CharArray = "changeit".toCharArray()

    fun keystore(dir: File, cn: String, ca: Boolean): File {
        Security.addProvider(BouncyCastleProvider())
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = Instant.now()
        val subject = X500Name("CN=$cn")
        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
            subject, keyPair.public
        )
        if (ca) builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)))
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, password)
        ks.setKeyEntry(if (ca) "ca" else "leaf", keyPair.private, password, arrayOf<X509Certificate>(cert))
        val file = File(dir, "${if (ca) "ca" else "srv"}-${System.nanoTime()}.p12")
        file.outputStream().use { ks.store(it, password) }
        return file
    }
}
