package expedition.engine.tls

import expedition.engine.UpstreamClientAuth
import expedition.tls.BurpCertificateProvider
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

object TcpTlsSupport {
    fun serverContext(provider: BurpCertificateProvider, host: String): SslContext {
        val (leafCert, leafKey) = provider.leafCertificateFor(host)
        return SslContextBuilder.forServer(leafKey, leafCert, provider.caCertificate).build()
    }

    // NOTE: upstream TLS trust is intentionally permissive (trusts any upstream
    // certificate). This is a security-testing proxy relaying to targets the user
    // controls; certificate pinning/validation of the upstream is out of scope for
    // v1. Upgrade path: add a per-listener "verify upstream certificate" toggle
    // backed by a real TrustManager.
    fun clientContext(auth: UpstreamClientAuth? = null): SslContext {
        val builder = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
        if (auth != null) {
            val ks = KeyStore.getInstance("PKCS12")
            auth.keystorePath.inputStream().use { ks.load(it, auth.keystorePassword) }
            val alias = ks.aliases().asSequence().firstOrNull { ks.isKeyEntry(it) }
                ?: throw IllegalStateException("No key entry in client keystore ${auth.keystorePath.path}")
            val key = ks.getKey(alias, auth.keystorePassword) as PrivateKey
            val chain = ks.getCertificateChain(alias).map { it as X509Certificate }.toTypedArray()
            builder.keyManager(key, *chain)
        }
        return builder.build()
    }
}
