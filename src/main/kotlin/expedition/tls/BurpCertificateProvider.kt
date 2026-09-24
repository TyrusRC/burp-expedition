package expedition.tls

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

class BurpCertificateProvider(
    keystorePath: File,
    keystorePassword: CharArray,
    caAlias: String? = null
) {
    val caCertificate: X509Certificate
    private val caKey: PrivateKey
    private val leafCache = ConcurrentHashMap<String, Pair<X509Certificate, PrivateKey>>()

    init {
        Security.addProvider(BouncyCastleProvider())
        val keystore = KeyStore.getInstance("PKCS12")
        keystorePath.inputStream().use { keystore.load(it, keystorePassword) }

        val alias = caAlias
            ?: keystore.aliases().asSequence().firstOrNull { keystore.isKeyEntry(it) }
            ?: throw IllegalStateException("No key entry found in keystore ${keystorePath.path}")

        caCertificate = keystore.getCertificate(alias) as X509Certificate
        caKey = keystore.getKey(alias, keystorePassword) as PrivateKey
    }

    fun leafCertificateFor(host: String): Pair<X509Certificate, PrivateKey> =
        leafCache.getOrPut(host) { generateLeafCertificate(host) }

    private fun generateLeafCertificate(host: String): Pair<X509Certificate, PrivateKey> {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)
        val keyPair = keyGen.generateKeyPair()

        val now = Instant.now()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(caCertificate.subjectX500Principal.name),
            BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofDays(1))),
            Date.from(now.plus(Duration.ofDays(365))),
            X500Name("CN=$host"),
            keyPair.public
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(caKey)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        return cert to keyPair.private
    }
}
