package expedition.engine

import expedition.registry.ConnectionRegistry
import expedition.registry.Protocol
import expedition.tls.BurpCertificateProvider
import io.netty.channel.nio.NioEventLoopGroup
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
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
import javax.net.ssl.*

class TcpListenerTlsTest {

    @TempDir
    lateinit var tempDir: File

    @Test
    fun `terminates client TLS with a Burp-CA-signed cert and decrypts to the upstream`() {
        Security.addProvider(BouncyCastleProvider())
        val (caKeystoreFile, caPassword) = writeCaKeystore(tempDir)
        val certProvider = BurpCertificateProvider(caKeystoreFile, caPassword)
        val upstreamKeystore = writeSelfSignedKeystore(tempDir, "upstream.test")

        TlsEchoServer(upstreamKeystore.first, upstreamKeystore.second).use { echo ->
            val boss = NioEventLoopGroup(1)
            val worker = NioEventLoopGroup()
            val registry = ConnectionRegistry()
            val config = ListenerConfig("tls1", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port, TlsMode.MITM)
            val listener = TcpListener(config, registry, boss, worker, certificateProvider = certProvider)
            try {
                val port = (listener.start().sync().channel().localAddress() as java.net.InetSocketAddress).port

                val clientTrustStore = KeyStore.getInstance("PKCS12").apply {
                    load(null, null)
                    setCertificateEntry("expedition-ca", certProvider.caCertificate)
                }
                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                tmf.init(clientTrustStore)
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, tmf.trustManagers, null)

                (sslContext.socketFactory.createSocket("127.0.0.1", port) as SSLSocket).use { client ->
                    client.startHandshake()
                    client.outputStream.write("secret".toByteArray())
                    client.outputStream.flush()
                    val buffer = ByteArray(6)
                    var total = 0
                    while (total < 6) {
                        val read = client.inputStream.read(buffer, total, 6 - total)
                        if (read < 0) break
                        total += read
                    }
                    assertEquals("secret", String(buffer))
                }

                waitUntil { registry.allMessages().isNotEmpty() }
                assertArrayEquals("secret".toByteArray(), registry.allMessages().first().rawBytes)
            } finally {
                listener.stop()
                boss.shutdownGracefully().sync()
                worker.shutdownGracefully().sync()
            }
        }
    }

    @Test
    fun `closes the connection cleanly when the client does not trust the loaded CA`() {
        Security.addProvider(BouncyCastleProvider())
        val (caKeystoreFile, caPassword) = writeCaKeystore(tempDir)
        val certProvider = BurpCertificateProvider(caKeystoreFile, caPassword)
        val upstreamKeystore = writeSelfSignedKeystore(tempDir, "upstream.test")

        TlsEchoServer(upstreamKeystore.first, upstreamKeystore.second).use { echo ->
            val boss = NioEventLoopGroup(1)
            val worker = NioEventLoopGroup()
            val registry = ConnectionRegistry()
            val config = ListenerConfig("tls2", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port, TlsMode.MITM)
            val listener = TcpListener(config, registry, boss, worker, certificateProvider = certProvider)
            try {
                val port = (listener.start().sync().channel().localAddress() as java.net.InetSocketAddress).port
                val client = SSLContext.getDefault().socketFactory.createSocket("127.0.0.1", port) as SSLSocket
                assertThrows(SSLException::class.java) { client.startHandshake() }
                client.close()
                waitUntil { registry.allConnections().any { it.closedAt != null } }
            } finally {
                listener.stop()
                boss.shutdownGracefully().sync()
                worker.shutdownGracefully().sync()
            }
        }
    }

    private fun writeCaKeystore(dir: File): Pair<File, CharArray> {
        val password = "changeit".toCharArray()
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = Instant.now()
        val subject = X500Name("CN=Test Expedition CA")
        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
            subject, keyPair.public
        ).addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)))
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, password)
        ks.setKeyEntry("ca", keyPair.private, password, arrayOf<X509Certificate>(cert))
        val file = File(dir, "ca-${System.nanoTime()}.p12")
        file.outputStream().use { ks.store(it, password) }
        return file to password
    }

    private fun writeSelfSignedKeystore(dir: File, cn: String): Pair<File, CharArray> {
        val password = "changeit".toCharArray()
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = Instant.now()
        val subject = X500Name("CN=$cn")
        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
            subject, keyPair.public
        )
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)))
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, password)
        ks.setKeyEntry("leaf", keyPair.private, password, arrayOf<X509Certificate>(cert))
        val file = File(dir, "upstream-${System.nanoTime()}.p12")
        file.outputStream().use { ks.store(it, password) }
        return file to password
    }
}

class TlsEchoServer(keystoreFile: File, password: CharArray) : AutoCloseable {
    private val serverSocket: SSLServerSocket
    val port: Int get() = serverSocket.localPort
    @Volatile private var running = true

    init {
        val ks = KeyStore.getInstance("PKCS12")
        keystoreFile.inputStream().use { ks.load(it, password) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, password)
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(kmf.keyManagers, null, null)
        serverSocket = sslContext.serverSocketFactory.createServerSocket(0) as SSLServerSocket
        Thread {
            while (running) {
                val client = try { serverSocket.accept() } catch (e: Exception) { break }
                Thread {
                    client.use { s ->
                        val input = s.getInputStream()
                        val output = s.getOutputStream()
                        val buffer = ByteArray(4096)
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            output.write(buffer, 0, read)
                            output.flush()
                        }
                    }
                }.start()
            }
        }.apply { isDaemon = true; start() }
    }

    override fun close() {
        running = false
        serverSocket.close()
    }
}
