package expedition.tls

import io.netty.util.NetUtil
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

/**
 * Mints per-host leaf certificates signed by the loaded (Burp) CA.
 *
 * The host is chosen per connection from the client's SNI (see `SniTlsRouter`), falling back
 * to the listener's upstream host. Leaves are kept in a bounded LRU cache ([maxCachedLeaves])
 * so a client spraying random SNI values cannot grow the heap without limit.
 */
class BurpCertificateProvider(
    keystorePath: File,
    keystorePassword: CharArray,
    caAlias: String? = null,
    private val maxCachedLeaves: Int = DEFAULT_MAX_CACHED_LEAVES
) {
    val caCertificate: X509Certificate
    private val caKey: PrivateKey
    private val random = SecureRandom()

    // Access-ordered LinkedHashMap = LRU; guarded by its own monitor.
    private val leafCache = object : LinkedHashMap<String, Pair<X509Certificate, PrivateKey>>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Pair<X509Certificate, PrivateKey>>) =
            size > maxCachedLeaves
    }

    // Server SslContexts keyed by (names, ALPN protocol), same LRU bound as the leaves.
    private val contextCache = object : LinkedHashMap<String, io.netty.handler.ssl.SslContext>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, io.netty.handler.ssl.SslContext>) =
            size > maxCachedLeaves
    }

    /**
     * ONE RSA key pair shared by every minted leaf: generating a 2048-bit key per SNI cost tens to
     * hundreds of ms each, so a client spraying random SNIs could pin the CPU. Signing a leaf with
     * the CA key is ~1 ms. (Leaves are throwaway MITM certificates; sharing the key is what Burp
     * and mitmproxy do too.) Generated lazily on first use.
     */
    private val leafKeyPair: java.security.KeyPair by lazy {
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    init {
        require(maxCachedLeaves > 0) { "maxCachedLeaves must be positive" }
        Security.addProvider(BouncyCastleProvider())
        val keystore = KeyStore.getInstance("PKCS12")
        keystorePath.inputStream().use { keystore.load(it, keystorePassword) }

        val alias = caAlias
            ?: keystore.aliases().asSequence().firstOrNull { keystore.isKeyEntry(it) }
            ?: throw IllegalStateException("No key entry found in keystore ${keystorePath.path}")

        caCertificate = keystore.getCertificate(alias) as X509Certificate
        caKey = keystore.getKey(alias, keystorePassword) as PrivateKey
    }

    /** Leaf whose CN and SAN are [host]. */
    fun leafCertificateFor(host: String): Pair<X509Certificate, PrivateKey> = leafCertificateFor(listOf(host))

    /**
     * Leaf for [names] (first one becomes the CN); every name goes into the SAN, typed as an
     * iPAddress for IP literals and a dNSName otherwise. Names are normalised (lower-case,
     * brackets/zone id/trailing dot stripped) and de-duplicated.
     */
    fun leafCertificateFor(names: List<String>): Pair<X509Certificate, PrivateKey> {
        val normalized = names.map(::normalizeHost).filter { it.isNotEmpty() }.distinct()
        require(normalized.isNotEmpty()) { "at least one host name is required" }
        val key = normalized.joinToString(",")
        synchronized(leafCache) { leafCache[key]?.let { return it } }
        // Generate outside the lock (RSA keygen is slow); first insert wins so callers racing
        // on the same host still observe a single cached instance.
        val minted = generateLeafCertificate(normalized)
        synchronized(leafCache) {
            leafCache[key]?.let { return it }
            leafCache[key] = minted
            return minted
        }
    }

    private fun contextKey(names: List<String>, alpn: String?): String =
        names.map(::normalizeHost).filter { it.isNotEmpty() }.distinct().joinToString(",") + "|" + (alpn ?: "")

    /** The cached server context for [names]/[alpn], or null (cheap; safe on an event loop). */
    fun cachedServerContext(names: List<String>, alpn: String? = null): io.netty.handler.ssl.SslContext? =
        synchronized(contextCache) { contextCache[contextKey(names, alpn)] }

    /**
     * Server-side [io.netty.handler.ssl.SslContext] presenting a leaf for [names]; when [alpn] is
     * set the context selects exactly that ALPN protocol (the one the upstream agreed to).
     * Cached (bounded LRU). May mint a leaf: call off the event loop on a cache miss.
     */
    fun serverContext(names: List<String>, alpn: String? = null): io.netty.handler.ssl.SslContext {
        val key = contextKey(names, alpn)
        synchronized(contextCache) { contextCache[key]?.let { return it } }
        val (leafCert, leafKey) = leafCertificateFor(names)
        val builder = io.netty.handler.ssl.SslContextBuilder.forServer(leafKey, leafCert, caCertificate)
        if (!alpn.isNullOrEmpty()) {
            builder.applicationProtocolConfig(
                io.netty.handler.ssl.ApplicationProtocolConfig(
                    io.netty.handler.ssl.ApplicationProtocolConfig.Protocol.ALPN,
                    io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                    io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                    alpn
                )
            )
        }
        val built = builder.build()
        synchronized(contextCache) {
            contextCache[key]?.let { return it }
            contextCache[key] = built
            return built
        }
    }

    /** Current number of cached leaves (bounded by [maxCachedLeaves]). */
    fun cachedLeafCount(): Int = synchronized(leafCache) { leafCache.size }

    private fun generateLeafCertificate(names: List<String>): Pair<X509Certificate, PrivateKey> {
        val keyPair = leafKeyPair

        val now = Instant.now()
        val builder = JcaX509v3CertificateBuilder(
            X500Name.getInstance(caCertificate.subjectX500Principal.encoded),
            randomSerial(),
            Date.from(now.minus(Duration.ofDays(1))),
            Date.from(now.plus(Duration.ofDays(365))),
            // Built RDN-by-RDN so a hostile name can never inject extra RDNs (",", "=").
            X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, names.first()).build(),
            keyPair.public
        )
        // A Subject Alternative Name is mandatory: clients that perform endpoint
        // identification (browsers, HttpClient, curl) reject a cert on CN alone.
        val sans = names.map { n ->
            if (isIpLiteral(n)) GeneralName(GeneralName.iPAddress, n) else GeneralName(GeneralName.dNSName, n)
        }
        builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(sans.toTypedArray()))
        // Subject/Authority Key Identifiers + BasicConstraints: OpenSSL 3.x clients (curl,
        // browsers, modern TLS libs) reject a leaf that lacks an Authority Key Identifier.
        val extUtils = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.public))
        builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate.publicKey))
        builder.addExtension(Extension.basicConstraints, false, org.bouncycastle.asn1.x509.BasicConstraints(false))
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(caKey)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        return cert to keyPair.private
    }

    /** 159 random bits: positive, non-zero and always within RFC 5280's 20-octet limit. */
    private fun randomSerial(): BigInteger {
        while (true) {
            val serial = BigInteger(159, random)
            if (serial.signum() > 0) return serial
        }
    }

    companion object {
        const val DEFAULT_MAX_CACHED_LEAVES = 512

        private val DNS_LABEL = Regex("^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

        /** Lower-case, strip `[]`, an IPv6 zone id and a trailing dot. */
        fun normalizeHost(host: String): String {
            var h = host.trim().lowercase()
            if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length - 1)
            if (h.contains(':')) h = h.substringBefore('%')
            return h.removeSuffix(".")
        }

        fun isIpLiteral(host: String): Boolean {
            val h = normalizeHost(host)
            return NetUtil.isValidIpV4Address(h) || NetUtil.isValidIpV6Address(h)
        }

        /**
         * True if [host] is usable as a certificate name: an IP literal or a syntactically valid
         * DNS name (labels 1-63 chars of [a-z0-9_-], total <= 253). Anything else (empty, spaces,
         * commas, wildcards...) is rejected so the caller can fall back to the upstream host.
         */
        fun isValidHostName(host: String?): Boolean {
            if (host == null) return false
            val h = normalizeHost(host)
            if (h.isEmpty() || h.length > 253) return false
            if (isIpLiteral(h)) return true
            return h.split('.').all { DNS_LABEL.matches(it) }
        }
    }
}
