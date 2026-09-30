package expedition.engine

import expedition.engine.tls.TcpTlsSupport
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

class TcpTlsSupportClientCertTest {

    @TempDir lateinit var tempDir: File
    private val password = "changeit".toCharArray()

    @Test
    fun `clientContext loads a client certificate keystore and builds a client context`() {
        Security.addProvider(BouncyCastleProvider())
        val ks = clientKeystore(File(tempDir, "client.p12"))
        val ctx = TcpTlsSupport.clientContext(UpstreamClientAuth(ks, password))
        assertTrue(ctx.isClient)
    }

    @Test
    fun `clientContext without auth still builds a client context`() {
        assertTrue(TcpTlsSupport.clientContext().isClient)
    }

    @Test
    fun `clientContext fails clearly when the client keystore has no key entry`() {
        val empty = File(tempDir, "empty.p12")
        val ks = KeyStore.getInstance("PKCS12"); ks.load(null, password)
        empty.outputStream().use { ks.store(it, password) }
        val error = assertThrows(IllegalStateException::class.java) {
            TcpTlsSupport.clientContext(UpstreamClientAuth(empty, password))
        }
        assertTrue(error.message!!.contains("key entry"))
    }

    private fun clientKeystore(file: File): File {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = Instant.now()
        val subject = X500Name("CN=proxy-client")
        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
            subject, kp.public
        )
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private))
        )
        val ks = KeyStore.getInstance("PKCS12"); ks.load(null, password)
        ks.setKeyEntry("client", kp.private, password, arrayOf<X509Certificate>(cert))
        file.outputStream().use { ks.store(it, password) }
        return file
    }
}
