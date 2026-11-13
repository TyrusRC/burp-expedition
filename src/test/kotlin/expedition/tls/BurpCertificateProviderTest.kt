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

    @Test
    fun `leaf cache is a bounded LRU`() {
        val provider = BurpCertificateProvider(keystoreFile, password, maxCachedLeaves = 2)
        val a = provider.leafCertificateFor("a.test")
        provider.leafCertificateFor("b.test")
        assertSame(a.first, provider.leafCertificateFor("a.test").first) // touch a -> b is eldest
        provider.leafCertificateFor("c.test")                             // evicts b
        assertEquals(2, provider.cachedLeafCount())
        assertSame(a.first, provider.leafCertificateFor("a.test").first)
        repeat(20) { provider.leafCertificateFor("h$it.test") }
        assertEquals(2, provider.cachedLeafCount())
        assertNotSame(a.first, provider.leafCertificateFor("a.test").first) // a was evicted and re-minted
    }

    @Test
    fun `serial numbers are random, positive and at most 20 octets`() {
        val provider = BurpCertificateProvider(keystoreFile, password)
        val serials = (1..5).map { provider.leafCertificateFor("s$it.test").first.serialNumber }
        assertEquals(5, serials.toSet().size)
        serials.forEach {
            assertTrue(it.signum() > 0)
            assertTrue(it.toByteArray().size <= 20)
            assertTrue(it.bitLength() > 64, "serial should not look like an epoch-ms counter: $it")
        }
    }

    @Test
    fun `SAN entries are typed as DNS name or IP address`() {
        val provider = BurpCertificateProvider(keystoreFile, password)
        val (leaf, _) = provider.leafCertificateFor(listOf("api.example.test", "10.1.2.3", "[::1]"))
        val sans = leaf.subjectAlternativeNames.map { (it[0] as Int) to (it[1] as String) }
        assertTrue(2 to "api.example.test" in sans, sans.toString())
        assertTrue(7 to "10.1.2.3" in sans, sans.toString())
        assertTrue(sans.any { it.first == 7 && (it.second == "0:0:0:0:0:0:0:1" || it.second == "::1") }, sans.toString())
        assertEquals("CN=api.example.test", leaf.subjectX500Principal.name)
    }

    @Test
    fun `a hostile name cannot inject extra subject RDNs`() {
        val provider = BurpCertificateProvider(keystoreFile, password)
        val (leaf, _) = provider.leafCertificateFor("evil,O=Injected")
        val subject = X500Name.getInstance(leaf.subjectX500Principal.encoded)
        assertEquals(1, subject.rdNs.size, subject.toString())
        assertTrue(subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.O).isEmpty(), subject.toString())
    }

    @Test
    fun `host name validation`() {
        assertTrue(BurpCertificateProvider.isValidHostName("a.example.test"))
        assertTrue(BurpCertificateProvider.isValidHostName("127.0.0.1"))
        assertTrue(BurpCertificateProvider.isValidHostName("::1"))
        assertFalse(BurpCertificateProvider.isValidHostName(null))
        assertFalse(BurpCertificateProvider.isValidHostName(""))
        assertFalse(BurpCertificateProvider.isValidHostName("a b.test"))
        assertFalse(BurpCertificateProvider.isValidHostName("a,b.test"))
        assertFalse(BurpCertificateProvider.isValidHostName("*.test"))
        assertFalse(BurpCertificateProvider.isValidHostName("a".repeat(64) + ".test"))
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
