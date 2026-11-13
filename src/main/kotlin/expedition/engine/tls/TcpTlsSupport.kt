package expedition.engine.tls

import expedition.engine.UpstreamClientAuth
import expedition.tls.BurpCertificateProvider
import io.netty.handler.ssl.ApplicationProtocolConfig
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

object TcpTlsSupport {
    fun serverContext(provider: BurpCertificateProvider, host: String): SslContext =
        serverContext(provider, listOf(host))

    /** Server context presenting a leaf for [names] (first = CN; all in the SAN); cached by the provider. */
    fun serverContext(provider: BurpCertificateProvider, names: List<String>, alpn: String? = null): SslContext =
        provider.serverContext(names, alpn)

    /** `[http/1.1]` if the client offered it, else nothing (used when the upstream can't be asked). */
    fun http11Only(clientAlpn: List<String>): List<String> =
        if ("http/1.1" in clientAlpn) listOf("http/1.1") else emptyList()

    /** Max leaf mints queued at once; beyond this, new-SNI handshakes are refused (SNI-flood guard). */
    const val MAX_PENDING_MINTS = 64

    private val mintThreads = AtomicLong(1)

    /**
     * Small bounded pool where leaf minting / SslContext building runs, OFF the Netty event loops.
     * The bounded queue + AbortPolicy is the rate limit: a client spraying random SNIs gets its
     * excess handshakes rejected instead of starving every other connection.
     */
    val mintExecutor: ExecutorService = ThreadPoolExecutor(
        2, 2, 30, TimeUnit.SECONDS, ArrayBlockingQueue(MAX_PENDING_MINTS),
        { r -> Thread(r, "expedition-tls-mint-${mintThreads.getAndIncrement()}").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy()
    ).apply { allowCoreThreadTimeOut(true) }

    // Client contexts keyed by (keystore path, mtime, password digest, ALPN offer): the PKCS#12
    // is read from disk once per configuration instead of on every connection (event loop).
    private val clientCache = object : LinkedHashMap<String, SslContext>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, SslContext>) = size > 64
    }

    private fun clientKey(auth: UpstreamClientAuth?, alpn: List<String>): String {
        val a = auth?.let {
            val f = it.keystorePath.absoluteFile
            val pw = MessageDigest.getInstance("SHA-256").digest(String(it.keystorePassword).toByteArray(Charsets.UTF_8))
            "${f.path}|${f.lastModified()}|${f.length()}|${pw.joinToString("") { b -> "%02x".format(b) }}"
        } ?: "-"
        return a + "|" + alpn.joinToString(",")
    }

    // NOTE: upstream TLS trust is intentionally permissive (trusts any upstream
    // certificate). This is a security-testing proxy relaying to targets the user
    // controls; certificate pinning/validation of the upstream is out of scope for
    // v1. Upgrade path: add a per-listener "verify upstream certificate" toggle
    // backed by a real TrustManager.
    /**
     * Upstream (client-side) context. [alpn] = protocols offered upstream (the client's own ALPN
     * offer, so the upstream picks what the client would have got). Cached per configuration.
     */
    fun clientContext(auth: UpstreamClientAuth? = null, alpn: List<String> = emptyList()): SslContext {
        val key = clientKey(auth, alpn)
        synchronized(clientCache) { clientCache[key]?.let { return it } }
        val builder = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
        if (auth != null) {
            val ks = KeyStore.getInstance("PKCS12")
            auth.keystorePath.inputStream().use { ks.load(it, auth.keystorePassword) }
            val alias = ks.aliases().asSequence().firstOrNull { ks.isKeyEntry(it) }
                ?: throw IllegalStateException("No key entry in client keystore ${auth.keystorePath.path}")
            val key0 = ks.getKey(alias, auth.keystorePassword) as PrivateKey
            val chain = ks.getCertificateChain(alias).map { it as X509Certificate }.toTypedArray()
            builder.keyManager(key0, *chain)
        }
        if (alpn.isNotEmpty()) {
            builder.applicationProtocolConfig(
                ApplicationProtocolConfig(
                    ApplicationProtocolConfig.Protocol.ALPN,
                    ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                    ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                    alpn
                )
            )
        }
        val built = builder.build()
        synchronized(clientCache) { clientCache[key] = built }
        return built
    }
}
