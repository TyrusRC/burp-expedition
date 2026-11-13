package expedition.engine

import expedition.engine.tls.StartTlsCoordinator
import expedition.pipeline.MessageGate
import expedition.registry.Direction
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.ssl.SslHandler
import io.netty.util.concurrent.Future
import io.netty.util.concurrent.Promise
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

class TcpConnection(
    val connectionId: Long,
    private val config: ListenerConfig,
    private val clientChannel: Channel,
    private val messageGate: MessageGate,
    private val startTls: StartTlsCoordinator? = null,
    private val maxPendingBytes: Long = DEFAULT_MAX_PENDING_BYTES
) {
    @Volatile private var upstreamChannel: Channel? = null
    @Volatile private var upstreamReady = false
    private val pendingWrites = Collections.synchronizedList(mutableListOf<ByteBuf>())
    @Volatile private var closed = false
    @Volatile private var passthrough = false
    private var pendingBytes = 0L   // guarded by pendingWrites

    // One framer per direction; each is locked on itself because close() (and its remainder
    // flush) can run on the other leg's event loop while a read is being framed.
    private val clientFramer = config.framing.newFramer { warnFraming(Direction.CLIENT_TO_UPSTREAM, it) }
    private val upstreamFramer = config.framing.newFramer { warnFraming(Direction.UPSTREAM_TO_CLIENT, it) }
    private val framersFlushed = AtomicBoolean(false)

    init {
        // Rules layer (expedition.rules) may answer, delay or close this connection itself.
        messageGate.attachConnection(connectionId, expedition.rules.NettyConnectionControl(config.name, config.upstreamHost, config.upstreamPort, clientChannel) { close() })
    }

    private fun warnFraming(direction: Direction, message: String) {
        System.err.println("Expedition [conn $connectionId ${direction.name}]: $message")
        messageGate.recordNote(connectionId, direction, "WARNING: $message")
    }

    /** Frame a chunk; once the remainder has been flushed on close, late chunks pass through as-is. */
    private fun frame(framer: expedition.framing.Framer, bytes: ByteArray): List<ByteArray> =
        synchronized(framer) { if (framersFlushed.get()) listOf(bytes) else framer.feed(bytes) }

    /**
     * Opens the upstream leg (chained through [ListenerConfig.upstreamProxy] if set).
     *
     * Without [onConnectResult] a failed connect simply closes the connection. With it, the
     * callback receives `null` once the upstream is reachable — for a chained proxy, once the
     * proxy tunnel is established — or the failure cause; on failure the caller is responsible
     * for closing (so it can e.g. send a SOCKS5 error reply first).
     */
    fun connectUpstream(
        workerGroup: EventLoopGroup,
        onConnectResult: ((Throwable?) -> Unit)? = null,
        pipelineBuilder: (SocketChannel) -> Unit
    ) {
        var proxyHandler: io.netty.handler.proxy.ProxyHandler? = null
        val bootstrap = Bootstrap()
            .group(workerGroup)
            .channel(NioSocketChannel::class.java)
            .handler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(upstream: SocketChannel) {
                    // Chain the upstream leg through an outbound SOCKS5 proxy if configured.
                    // The ProxyHandler negotiates to the real destination (the bootstrap's
                    // connect target) and buffers writes until the tunnel is established.
                    config.upstreamProxy?.let { p ->
                        val h = io.netty.handler.proxy.Socks5ProxyHandler(java.net.InetSocketAddress(p.host, p.port))
                        proxyHandler = h
                        upstream.pipeline().addLast(PROXY_HANDLER, h)
                    }
                    pipelineBuilder(upstream)
                }
            })
        bootstrap.connect(config.upstreamHost, config.upstreamPort).addListener(ChannelFutureListener { f ->
            if (f.isSuccess) {
                var closedMeanwhile = false
                synchronized(pendingWrites) {
                    if (closed) {
                        closedMeanwhile = true
                    } else {
                        upstreamChannel = f.channel()
                        pendingWrites.forEach { f.channel().writeAndFlush(it) }
                        pendingWrites.clear()
                        pendingBytes = 0
                        upstreamReady = true
                    }
                }
                if (closedMeanwhile) {
                    // The client left while we were dialling: close() could not see this channel,
                    // so close it here or the upstream socket leaks.
                    f.channel().close()
                    onConnectResult?.invoke(java.nio.channels.ClosedChannelException())
                    return@ChannelFutureListener
                }
                if (onConnectResult != null) {
                    val ph = proxyHandler
                    if (ph == null) onConnectResult(null)
                    else ph.connectFuture().addListener { pf -> onConnectResult(if (pf.isSuccess) null else pf.cause()) }
                }
            } else if (onConnectResult != null) {
                onConnectResult(f.cause())
            } else {
                close()
            }
        })
    }

    /**
     * Switch to raw relay: from now on bytes in both directions bypass framing and the message
     * gate (no intercept / match-replace on ciphertext). A note marks the connection in history.
     */
    fun enterPassthrough(sni: String?) {
        passthrough = true
        messageGate.recordNote(
            connectionId, Direction.CLIENT_TO_UPSTREAM,
            "TLS PASSTHROUGH (SNI=${sni ?: "-"}): relayed raw, not decrypted"
        )
    }

    val isPassthrough: Boolean get() = passthrough

    /**
     * Start TLS on the established upstream leg (SNI / peer host = [peerHost]). The SslHandler
     * goes right before the relay handler, i.e. after any chained-proxy handler.
     */
    fun startUpstreamTls(peerHost: String, alpn: List<String> = emptyList()): Future<String?>? {
        val result = if (alpn.isNotEmpty()) newAlpnPromise() else null
        val up = upstreamChannel ?: run {
            // Lazy dial (mock rules): TLS goes into the pipeline when the upstream is dialled.
            if (lazyDial != null) lazyUpstreamTls = Triple(peerHost, alpn, result)
            else result?.tryFailure(IllegalStateException("upstream not connected"))
            return result
        }
        up.eventLoop().execute {
            if (up.pipeline().get(UPSTREAM_SSL_HANDLER) != null || !up.isOpen) {
                result?.tryFailure(IllegalStateException("upstream TLS already started or channel closed"))
                return@execute
            }
            val ssl = upstreamTlsHandler(up, peerHost, alpn, result)
            if (up.pipeline().get(UPSTREAM_HANDLER) != null) up.pipeline().addBefore(UPSTREAM_HANDLER, UPSTREAM_SSL_HANDLER, ssl)
            else up.pipeline().addLast(UPSTREAM_SSL_HANDLER, ssl)
        }
        return result
    }

    /** Pending upstream TLS (peer, ALPN offer, result) to install when a lazy dial happens. */
    @Volatile private var lazyUpstreamTls: Triple<String, List<String>, Promise<String?>?>? = null

    /** Adds the deferred upstream SslHandler (if [startUpstreamTls] ran before the lazy dial). */
    internal fun installLazyUpstreamTls(upstream: Channel) {
        val (peer, alpn, result) = lazyUpstreamTls ?: return
        upstream.pipeline().addLast(UPSTREAM_SSL_HANDLER, upstreamTlsHandler(upstream, peer, alpn, result))
    }

    /**
     * Upstream-leg SslHandler offering [alpn]; [result] (if any) completes with the protocol the
     * upstream selected (null = none) once its handshake is done, or fails with it.
     */
    fun upstreamTlsHandler(upstream: Channel, peerHost: String, alpn: List<String>, result: Promise<String?>?): SslHandler {
        val ssl = expedition.engine.tls.TcpTlsSupport.clientContext(config.upstreamClientAuth, alpn)
            .newHandler(upstream.alloc(), peerHost, config.upstreamPort)
        if (result != null) {
            ssl.handshakeFuture().addListener { f ->
                if (f.isSuccess) result.trySuccess(ssl.applicationProtocol()) else result.tryFailure(f.cause())
            }
        }
        return ssl
    }

    /** A promise for the upstream ALPN result; fails if the client leg closes first. */
    fun newAlpnPromise(): Promise<String?> = clientChannel.eventLoop().newPromise<String?>().also { p ->
        clientChannel.closeFuture().addListener { p.tryFailure(java.nio.channels.ClosedChannelException()) }
    }

    // ── lazy dial (an active mock rule may answer without any upstream) ──────────

    @Volatile private var lazyDial: (() -> Unit)? = null
    private val dialStarted = AtomicBoolean(false)

    /** True when the upstream is dialled only once something must actually be sent to it. */
    val isLazy: Boolean get() = lazyDial != null

    /** Defer the upstream connect: [dial] runs the first time bytes must go upstream. */
    fun deferDial(dial: () -> Unit) { lazyDial = dial }

    @Volatile private var clientSpoke = false

    /** Lazy dial safety net: dial after [ms] if the client has sent nothing (server-first protocols). */
    fun dialIfClientSilent(ms: Long = LAZY_SILENT_DIAL_MS) {
        clientChannel.eventLoop().schedule({ if (!clientSpoke && !closed) dialNow() }, ms, java.util.concurrent.TimeUnit.MILLISECONDS)
    }

    /** Run the deferred dial now (e.g. TLS passthrough needs the raw upstream at once). */
    fun dialNow() {
        val d = lazyDial ?: return
        if (dialStarted.compareAndSet(false, true)) d()
    }

    /**
     * Connect for a lazy dial: on failure, an HTTP request waiting for this upstream is answered
     * `502 Bad Gateway` (through the gate, so rules/history see it) and the connection closes.
     */
    fun connectUpstreamLazily(workerGroup: EventLoopGroup, pipelineBuilder: (SocketChannel) -> Unit) {
        connectUpstream(workerGroup, onConnectResult = { cause -> if (cause != null) failLazyDial(cause) }) { upstream ->
            pipelineBuilder(upstream)
        }
    }

    private fun failLazyDial(cause: Throwable) {
        val http = synchronized(pendingWrites) { pendingWrites.firstOrNull()?.let(::looksLikeHttpRequest) ?: false }
        clientChannel.eventLoop().execute {
            if (http && !passthrough && !closed) {
                val body = "Expedition: upstream ${config.upstreamHost}:${config.upstreamPort} unreachable: ${cause.message ?: cause.javaClass.simpleName}"
                    .toByteArray(Charsets.UTF_8)
                val head = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n" +
                    "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n"
                handleUpstreamBytes(Unpooled.wrappedBuffer(head.toByteArray(Charsets.ISO_8859_1) + body))
            }
            close()
        }
    }

    private fun looksLikeHttpRequest(buf: ByteBuf): Boolean {
        val n = minOf(buf.readableBytes(), 16)
        val s = buf.toString(buf.readerIndex(), n, Charsets.ISO_8859_1)
        return Regex("^[A-Z]{3,10} ").containsMatchIn(s)
    }

    fun handleClientBytes(buf: ByteBuf) {
        clientSpoke = true
        if (passthrough) {
            sendUpstream(buf)
            return
        }
        val bytes = ByteBufUtil.getBytes(buf)
        buf.release()
        frame(clientFramer, bytes).forEach(::processClientMessage)
    }

    private fun processClientMessage(bytes: ByteArray) {
        messageGate.process(connectionId, Direction.CLIENT_TO_UPSTREAM, bytes) { finalBytes ->
            // Mark the STARTTLS request BEFORE writing upstream, so the flag is set before the
            // server's go-ahead can race back (loopback is fast enough to lose that ordering).
            startTls?.onClientForwarded(finalBytes)
            sendUpstream(Unpooled.wrappedBuffer(finalBytes))
        }
    }

    /**
     * Write to the upstream, or queue until it is connected. The queue is capped at
     * [maxPendingBytes]: a client that keeps sending while the upstream never comes up would
     * otherwise grow it without bound — on overflow the connection is closed with a warning.
     */
    private fun sendUpstream(buf: ByteBuf) {
        var overflow = false
        synchronized(pendingWrites) {
            when {
                closed -> buf.release()                                     // dropped after close
                upstreamReady -> upstreamChannel!!.writeAndFlush(buf)
                pendingBytes + buf.readableBytes() > maxPendingBytes -> { buf.release(); overflow = true }
                else -> { pendingBytes += buf.readableBytes(); pendingWrites.add(buf) }
            }
        }
        if (!upstreamReady && !closed) dialNow()
        if (overflow) {
            val msg = "pending upstream writes exceeded $maxPendingBytes bytes before the upstream connected; closing connection"
            System.err.println("Expedition [conn $connectionId]: $msg")
            messageGate.recordNote(connectionId, Direction.CLIENT_TO_UPSTREAM, "WARNING: $msg")
            close()
        }
    }

    fun handleUpstreamBytes(buf: ByteBuf) {
        if (passthrough) {
            clientChannel.writeAndFlush(buf)
            return
        }
        val bytes = ByteBufUtil.getBytes(buf)
        buf.release()
        frame(upstreamFramer, bytes).forEach(::processUpstreamMessage)
    }

    private fun processUpstreamMessage(bytes: ByteArray) {
        messageGate.process(connectionId, Direction.UPSTREAM_TO_CLIENT, bytes) { finalBytes ->
            val up = upstreamChannel
            if (startTls != null && up != null && startTls.isGoAhead(finalBytes)) {
                // Write the go-ahead AND insert the TLS handlers in one client-loop task: the 220
                // traverses the pipeline (plaintext) before addFirst, and no client read (the
                // ClientHello) can interleave — so the SslHandler is always in place first.
                clientChannel.eventLoop().execute {
                    clientChannel.writeAndFlush(Unpooled.wrappedBuffer(finalBytes))
                    startTls.upgrade(clientChannel, this)
                }
            } else {
                clientChannel.writeAndFlush(Unpooled.wrappedBuffer(finalBytes))
            }
        }
    }

    fun close() {
        // Flush each direction's partial message through the gate exactly once, BEFORE marking
        // the connection closed, so it is recorded and (if the peer leg is still writable)
        // delivered ahead of the channel close. Passthrough framers never hold a remainder.
        if (framersFlushed.compareAndSet(false, true)) {
            synchronized(clientFramer) { clientFramer.flush() }?.let(::processClientMessage)
            synchronized(upstreamFramer) { upstreamFramer.flush() }?.let(::processUpstreamMessage)
        }
        messageGate.detachConnection(connectionId)
        synchronized(pendingWrites) {
            if (closed) return
            closed = true
            pendingWrites.forEach { it.release() }   // release any never-flushed buffers
            pendingWrites.clear()
            pendingBytes = 0
        }
        clientChannel.close()
        upstreamChannel?.close()
    }

    companion object {
        const val PROXY_HANDLER = "expedition-upstream-proxy"
        const val UPSTREAM_SSL_HANDLER = "expedition-upstream-ssl"
        const val UPSTREAM_HANDLER = "expedition-upstream"
        /** Max bytes buffered for a not-yet-connected upstream before the connection is dropped. */
        const val DEFAULT_MAX_PENDING_BYTES = 8L * 1024 * 1024
        /** Lazy dial: how long a silent client waits before the upstream is dialled anyway. */
        const val LAZY_SILENT_DIAL_MS = 300L
    }
}
