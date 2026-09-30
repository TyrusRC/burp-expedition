package expedition.tls

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.time.Duration
import java.time.Instant
import java.util.Date

class BurpCertificateProviderTest {

    @TempDir
    lateinit var tempDir: File

    private lateinit var keystoreFile: File
    private val password = "changeit".toCharArray()

    @BeforeEach
    fun setUp() {
        Security.addProvider(BouncyCastleProvider())
        keystoreFile = File(tempDir, "test-ca.p12")
        writeThrowawayCaKeystore(keystoreFile, password)
    }

    @Test
    fun `mints a leaf certificate issued by the loaded CA`() {
        val provider = BurpCertificateProvider(keystoreFile, password)

        val (leaf, _) = provider.leafCertificateFor("example.test")

        assertEquals(provider.caCertificate.subjectX500Principal, leaf.issuerX500Principal)
        assertEquals("CN=example.test", leaf.subjectX500Principal.name)
    }

    @Test
    fun `minted leaf carries subject and authority key identifiers`() {
        val provider = BurpCertificateProvider(keystoreFile, password)
        val (leaf, _) = provider.leafCertificateFor("example.test")
        // OpenSSL 3.x clients reject a leaf without an Authority Key Identifier.
        assertNotNull(leaf.getExtensionValue("2.5.29.14"), "missing Subject Key Identifier")
        assertNotNull(leaf.getExtensionValue("2.5.29.35"), "missing Authority Key Identifier")
    }

    @Test
    fun `caches the leaf certificate for repeated lookups of the same host`() {
        val provider = BurpCertificateProvider(keystoreFile, password)

        val first = provider.leafCertificateFor("example.test")
        val second = provider.leafCertificateFor("example.test")

        assertSame(first.first, second.first)
    }

    @Test
    fun `throws a clear error when the keystore file does not contain a usable key entry`() {
        val emptyKeystore = File(tempDir, "empty.p12")
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, password)
        emptyKeystore.outputStream().use { ks.store(it, password) }

        val error = assertThrows(IllegalStateException::class.java) {
            BurpCertificateProvider(emptyKeystore, password)
        }
        assertTrue(error.message!!.contains("key entry"))
    }

    @Test
    fun `throws a clear error when the keystore file is missing`() {
        val missing = File(tempDir, "does-not-exist.p12")

        assertThrows(java.io.IOException::class.java) {
            BurpCertificateProvider(missing, password)
        }
    }

    private fun writeThrowawayCaKeystore(file: File, password: CharArray) {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)
        val keyPair = keyGen.generateKeyPair()

        val now = Instant.now()
        val subject = X500Name("CN=Test Expedition CA")
        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
            subject, keyPair.public
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, password)
        ks.setKeyEntry("ca", keyPair.private, password, arrayOf(cert))
        file.outputStream().use { ks.store(it, password) }
    }
}
