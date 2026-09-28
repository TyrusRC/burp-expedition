package expedition.engine.tls

import expedition.tls.BurpCertificateProvider
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory

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
    fun clientContext(): SslContext =
        SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build()
}
