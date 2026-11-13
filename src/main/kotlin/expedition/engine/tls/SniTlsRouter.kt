package expedition.engine.tls

import expedition.tls.BurpCertificateProvider
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.ssl.AbstractSniHandler
import io.netty.handler.ssl.SslContext
import io.netty.util.concurrent.Future
import java.nio.channels.ClosedChannelException
import java.util.concurrent.RejectedExecutionException

/** What to do with a client's TLS session, decided from its ClientHello. */
sealed class TlsDecision {
    /**
     * Terminate TLS with a leaf for [certNames]; [sni] is the validated client SNI (if any) and
     * [alpn] the ALPN protocols the client offered (empty = no ALPN extension).
     */
    data class Mitm(val sni: String?, val certNames: List<String>, val alpn: List<String> = emptyList()) : TlsDecision()

    /** Relay the TLS bytes untouched (SNI matched a `tls_passthrough` pattern). */
    data class Passthrough(val sni: String) : TlsDecision()
}

/**
 * Sits first on the client leg, buffers the ClientHello, and routes the session:
 * - SNI matches [passthrough] → [TlsDecision.Passthrough]: removes itself (the buffered
 *   ClientHello flows on unchanged) so the bytes are relayed raw.
 * - otherwise → [TlsDecision.Mitm]: replaces itself with an SslHandler whose leaf is minted for
 *   the SNI (plus [fallbackHost] in the SAN), or for [fallbackHost] alone when the client sent
 *   no SNI or an invalid one.
 *
 * [onDecision] runs as soon as the ClientHello is parsed, BEFORE the pipeline is changed, so
 * callers can set up the upstream leg / raw mode before the buffered ClientHello is released.
 *
 * ALPN: for a MITM decision where the client offered ALPN, [onDecision] may return a future of
 * the protocol the UPSTREAM selected (callers offer the client's own list upstream). The client
 * handshake is then held until the upstream handshake is done and the client-facing context
 * selects exactly that protocol — so an h2-only (e.g. gRPC) client gets h2 when the server
 * speaks it, and the bytes are relayed as-is. Returning null (no upstream yet, e.g. lazy dial)
 * deliberately selects `http/1.1` when the client offered it, else no ALPN.
 *
 * A leaf/context not yet cached is minted on [TcpTlsSupport.mintExecutor], never on the event
 * loop; when that bounded pool is saturated (SNI flood) the handshake is refused.
 */
class SniTlsRouter(
    private val provider: BurpCertificateProvider,
    private val fallbackHost: String,
    private val passthrough: TlsPassthroughMatcher,
    /** Runs once the client-facing MITM handshake succeeded (not for passthrough). */
    private val onMitmHandshake: () -> Unit = {},
    private val onDecision: (ChannelHandlerContext, TlsDecision) -> Future<String?>?
) : AbstractSniHandler<SniTlsRouter.Routed>() {

    class Routed(val decision: TlsDecision, val sslContext: SslContext?)

    private var clientAlpn: List<String> = emptyList()

    override fun lookup(ctx: ChannelHandlerContext, clientHello: ByteBuf?): Future<Routed> {
        clientAlpn = clientHello?.let { runCatching { parseAlpn(it) }.getOrDefault(emptyList()) } ?: emptyList()
        return super.lookup(ctx, clientHello)
    }

    override fun lookup(ctx: ChannelHandlerContext, hostname: String?): Future<Routed> {
        val decision = decide(hostname, fallbackHost, passthrough, clientAlpn)
        val upstreamAlpn = onDecision(ctx, decision)
        if (decision !is TlsDecision.Mitm) return ctx.executor().newSucceededFuture(Routed(decision, null))

        val promise = ctx.executor().newPromise<Routed>()
        ctx.channel().closeFuture().addListener { promise.tryFailure(ClosedChannelException()) }
        fun build(alpn: String?) {
            provider.cachedServerContext(decision.certNames, alpn)?.let { promise.trySuccess(Routed(decision, it)); return }
            try {
                TcpTlsSupport.mintExecutor.execute {
                    try {
                        promise.trySuccess(Routed(decision, provider.serverContext(decision.certNames, alpn)))
                    } catch (e: Throwable) {
                        promise.tryFailure(e)
                    }
                }
            } catch (e: RejectedExecutionException) {
                promise.tryFailure(IllegalStateException("too many TLS leaf certificates being minted; refusing handshake", e))
            }
        }
        when {
            decision.alpn.isEmpty() -> build(null)
            upstreamAlpn == null -> build(if ("http/1.1" in decision.alpn) "http/1.1" else null)
            else -> upstreamAlpn.addListener { f ->
                if (f.isSuccess) {
                    // Only select something the client actually offered (else: no ALPN).
                    build((f.now as String?)?.takeIf { it in decision.alpn })
                } else {
                    promise.tryFailure(f.cause())
                }
            }
        }
        return promise
    }

    override fun onLookupComplete(ctx: ChannelHandlerContext, hostname: String?, future: Future<Routed>) {
        if (!future.isSuccess) throw future.cause()
        val routed = future.now
        when (routed.decision) {
            is TlsDecision.Passthrough -> ctx.pipeline().remove(this)
            is TlsDecision.Mitm -> {
                val ssl = routed.sslContext!!.newHandler(ctx.alloc())
                ssl.handshakeFuture().addListener { if (it.isSuccess) runCatching(onMitmHandshake) }
                ctx.pipeline().replace(this, CLIENT_SSL_HANDLER, ssl)
            }
        }
    }

    companion object {
        const val NAME = "expedition-sni-router"
        const val CLIENT_SSL_HANDLER = "expedition-client-ssl"

        fun decide(
            hostname: String?,
            fallbackHost: String,
            passthrough: TlsPassthroughMatcher,
            alpn: List<String> = emptyList()
        ): TlsDecision {
            val sni = hostname?.takeIf { BurpCertificateProvider.isValidHostName(it) }
                ?.let(BurpCertificateProvider::normalizeHost)
            if (sni != null && passthrough.matches(sni)) return TlsDecision.Passthrough(sni)
            val names = if (sni != null) listOf(sni, fallbackHost) else listOf(fallbackHost)
            return TlsDecision.Mitm(sni, names.filter { BurpCertificateProvider.isValidHostName(it) }
                .ifEmpty { listOf(fallbackHost) }, alpn)
        }

        /**
         * ALPN protocol names from a ClientHello body (starting at client_version, as handed to
         * [lookup]); empty when absent or malformed. Does not move the buffer's indices.
         */
        fun parseAlpn(hello: ByteBuf): List<String> {
            var o = hello.readerIndex() + 34                       // client_version + random
            val end = hello.writerIndex()
            fun need(n: Int) = o + n <= end
            if (!need(1)) return emptyList()
            o += 1 + hello.getUnsignedByte(o)                     // session id
            if (!need(2)) return emptyList()
            o += 2 + hello.getUnsignedShort(o)                    // cipher suites
            if (!need(1)) return emptyList()
            o += 1 + hello.getUnsignedByte(o)                     // compression methods
            if (!need(2)) return emptyList()
            val extEnd = minOf(end, o + 2 + hello.getUnsignedShort(o))
            o += 2
            while (o + 4 <= extEnd) {
                val type = hello.getUnsignedShort(o)
                val len = hello.getUnsignedShort(o + 2)
                o += 4
                if (o + len > extEnd) return emptyList()
                if (type == 16 && len >= 2) {                      // application_layer_protocol_negotiation
                    val out = mutableListOf<String>()
                    var p = o + 2
                    val listEnd = minOf(o + len, o + 2 + hello.getUnsignedShort(o))
                    while (p < listEnd) {
                        val n = hello.getUnsignedByte(p).toInt()
                        p += 1
                        if (n == 0 || p + n > listEnd) break
                        out += hello.toString(p, n, Charsets.US_ASCII)
                        p += n
                    }
                    return out
                }
                o += len
            }
            return emptyList()
        }
    }
}
