package expedition.tls

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class DefaultCaTest {

    @TempDir lateinit var dir: File
    private val pw = "expedition".toCharArray()

    @Test
    fun `generates a loadable CA that can mint leaves`() {
        val p12 = DefaultCa.ensureDefaultCa(dir, pw)
        assertTrue(p12.exists())
        val provider = BurpCertificateProvider(p12, pw)
        assertTrue(provider.caCertificate.subjectX500Principal.name.contains("Expedition"))
        val (leaf, _) = provider.leafCertificateFor("example.test")
        assertEquals(provider.caCertificate.subjectX500Principal, leaf.issuerX500Principal)
    }

    @Test
    fun `is idempotent — reuses the existing keystore instead of regenerating`() {
        val first = DefaultCa.ensureDefaultCa(dir, pw).readBytes()
        val second = DefaultCa.ensureDefaultCa(dir, pw).readBytes()
        assertArrayEquals(first, second)
    }

    @Test
    fun `writes a PEM cert for installing in clients`() {
        DefaultCa.ensureDefaultCa(dir, pw)
        val crt = File(dir, "expedition-ca.crt")
        assertTrue(crt.exists())
        assertTrue(crt.readText().contains("BEGIN CERTIFICATE"))
    }
}
