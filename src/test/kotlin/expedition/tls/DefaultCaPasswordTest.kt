package expedition.tls

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class DefaultCaPasswordTest {

    @TempDir lateinit var dir: File

    @Test
    fun `fresh dir with no env generates a random password stored owner-only`() {
        val pw = DefaultCa.resolvePassword(dir, null)
        val stored = File(dir, "expedition-ca.pass")
        assertTrue(stored.exists())
        assertEquals(String(pw), stored.readText().trim())
        assertFalse(String(pw) == DefaultCa.LEGACY_PASSWORD)
        assertTrue(pw.size >= 20, "random password should be long")
    }

    @Test
    fun `password is stable across calls once stored`() {
        val first = String(DefaultCa.resolvePassword(dir, null))
        DefaultCa.ensureDefaultCa(dir, first.toCharArray())
        assertEquals(first, String(DefaultCa.resolvePassword(dir, null)))
    }

    @Test
    fun `env password is used for a fresh CA and the CA opens with it`() {
        val pw = DefaultCa.resolvePassword(dir, "from-env")
        assertEquals("from-env", String(pw))
        val p12 = DefaultCa.ensureDefaultCa(dir, pw)
        BurpCertificateProvider(p12, pw) // throws if the keystore cannot be opened
    }

    @Test
    fun `existing CA with legacy password still opens without env`() {
        // A CA minted before per-machine passwords: keystore sealed with the legacy password, no pass file.
        val p12 = DefaultCa.ensureDefaultCa(dir, DefaultCa.LEGACY_PASSWORD.toCharArray())
        assertFalse(File(dir, "expedition-ca.pass").exists())

        val pw = DefaultCa.resolvePassword(dir, null)
        assertEquals(DefaultCa.LEGACY_PASSWORD, String(pw))
        BurpCertificateProvider(p12, pw)
    }

    @Test
    fun `existing CA still opens with the legacy password when env is set to something else`() {
        val p12 = DefaultCa.ensureDefaultCa(dir, DefaultCa.LEGACY_PASSWORD.toCharArray())
        val pw = DefaultCa.resolvePassword(dir, "wrong-env-value")
        assertEquals(DefaultCa.LEGACY_PASSWORD, String(pw))
        BurpCertificateProvider(p12, pw)
    }
}
