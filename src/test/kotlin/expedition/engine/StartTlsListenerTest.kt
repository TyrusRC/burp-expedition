package expedition.engine

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.pipeline.MessageGate
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
import java.io.InputStream
import java.math.BigInteger
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date
import javax.net.ssl.*

class StartTlsListenerTest {

    @TempDir lateinit var tempDir: File
    private val password = "changeit".toCharArray()

    @Test
    fun `upgrades a plaintext connection to TLS on STARTTLS and MITMs the rest`() {
        Security.addProvider(BouncyCastleProvider())
        val caFile = keystore(File(tempDir, "ca.p12"), "Test CA", ca = true)
        val certProvider = BurpCertificateProvider(caFile, password)
        val serverFile = keystore(File(tempDir, "server.p12"), "upstream.test", ca = false)

        StartTlsEchoServer(serverFile, password).use { echo ->
            val boss = NioEventLoopGroup(1); val worker = NioEventLoopGroup()
            val registry = ConnectionRegistry()
            val gate = MessageGate(registry, InterceptController(), MatchReplaceEngine()) { _, _, _, _ -> }
            val config = ListenerConfig("stls", Protocol.TCP, "127.0.0.1", 0, "127.0.0.1", echo.port, TlsMode.STARTTLS)
            val listener = TcpListener(config, registry, boss, worker, gate, certProvider)
            try {
                val port = (listener.start().sync().channel().localAddress() as InetSocketAddress).port
                val plain = Socket("127.0.0.1", port)
                plain.getOutputStream().write("STARTTLS\r\n".toByteArray()); plain.getOutputStream().flush()
                val goAhead = readLine(plain.getInputStream())
                assertTrue(goAhead.startsWith("220"), "expected 220 go-ahead, got: $goAhead")

                val trust = KeyStore.getInstance("PKCS12").apply {
                    load(null, null); setCertificateEntry("ca", certProvider.caCertificate)
                }
                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
                val sslCtx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
                (sslCtx.socketFactory.createSocket(plain, "127.0.0.1", port, true) as SSLSocket).use { tls ->
                    tls.useClientMode = true
                    tls.startHandshake()
                    tls.outputStream.write("secret".toByteArray()); tls.outputStream.flush()
                    val buf = ByteArray(6); var total = 0
                    while (total < 6) { val r = tls.inputStream.read(buf, total, 6 - total); if (r < 0) break; total += r }
                    assertEquals("secret", String(buf))
                }
            } finally {
                listener.stop(); boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync()
            }
        }
    }

    private fun readLine(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0 || c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun keystore(file: File, cn: String, ca: Boolean): File {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = Instant.now()
        val subject = X500Name("CN=$cn")
        val builder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
            subject, kp.public
        )
        if (ca) builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private))
        )
        val ks = KeyStore.getInstance("PKCS12"); ks.load(null, password)
        ks.setKeyEntry("key", kp.private, password, arrayOf<X509Certificate>(cert))
        file.outputStream().use { ks.store(it, password) }
        return file
    }
}

/** Plaintext until it reads a line, replies "220 Go ahead", upgrades the socket to TLS, then echoes. */
class StartTlsEchoServer(keystoreFile: File, password: CharArray) : AutoCloseable {
    private val serverSocket = ServerSocket(0)
    val port: Int get() = serverSocket.localPort
    @Volatile private var running = true
    private val sslContext: SSLContext

    init {
        val ks = KeyStore.getInstance("PKCS12")
        keystoreFile.inputStream().use { ks.load(it, password) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, password) }
        sslContext = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        Thread {
            while (running) {
                val sock = try { serverSocket.accept() } catch (e: Exception) { break }
                Thread {
                    try {
                        val input = sock.getInputStream()
                        val out = sock.getOutputStream()
                        while (true) { val c = input.read(); if (c < 0 || c == '\n'.code) break } // consume STARTTLS line
                        out.write("220 Go ahead\r\n".toByteArray()); out.flush()
                        val ssl = sslContext.socketFactory.createSocket(sock, "127.0.0.1", sock.port, true) as SSLSocket
                        ssl.useClientMode = false
                        ssl.startHandshake()
                        val sin = ssl.inputStream; val sout = ssl.outputStream
                        val buf = ByteArray(4096)
                        while (true) { val r = sin.read(buf); if (r < 0) break; sout.write(buf, 0, r); sout.flush() }
                    } catch (e: Exception) { /* connection closed */ }
                }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true }.start()
    }

    override fun close() { running = false; serverSocket.close() }
}
