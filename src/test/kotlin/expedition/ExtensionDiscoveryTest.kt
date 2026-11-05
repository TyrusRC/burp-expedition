package expedition

import burp.api.montoya.BurpExtension
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.ServiceLoader

/**
 * Burp loads a Montoya extension by ServiceLoader lookup of burp.api.montoya.BurpExtension.
 * Without a META-INF/services/burp.api.montoya.BurpExtension entry naming our class, Burp
 * finds no entry point and the extension fails to load — so this is the single most important
 * check for a BApp Store submission. This test reproduces exactly what Burp does.
 */
class ExtensionDiscoveryTest {

    @Test
    fun `Burp discovers the extension entry point via ServiceLoader`() {
        val impls = ServiceLoader.load(BurpExtension::class.java).toList()
        assertTrue(impls.any { it is ExpeditionExtension },
            "ServiceLoader found no ExpeditionExtension — add META-INF/services/burp.api.montoya.BurpExtension. " +
            "Found: ${impls.map { it::class.java.name }}")
    }
}
