package expedition.rules

import expedition.registry.Direction
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelOption
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** What the rules layer may do to a live TCP connection besides relaying bytes. */
interface ConnectionControl {
    val listenerName: String
    val upstreamHost: String
    val upstreamPort: Int
    /** Write bytes straight to the client (bypassing the gate; used for `100 Continue`). */
    fun sendToClient(bytes: ByteArray)
    fun close()
    /** Abort with a TCP RST. */
    fun reset()
}

/** [ConnectionControl] over the client-side Netty channel of a [expedition.engine.TcpConnection]. */
class NettyConnectionControl(
    override val listenerName: String,
    override val upstreamHost: String,
    override val upstreamPort: Int,
    private val clientChannel: Channel,
    private val closer: () -> Unit,
) : ConnectionControl {
    override fun sendToClient(bytes: ByteArray) { clientChannel.writeAndFlush(Unpooled.wrappedBuffer(bytes)) }
    // Always hop to the event loop: close() re-enters the gate (framer flush) and must not run
    // while a rule session holds its lock on another thread.
    override fun close() { clientChannel.eventLoop().execute { closer() } }
    override fun reset() {
        clientChannel.eventLoop().execute {
            runCatching { clientChannel.config().setOption(ChannelOption.SO_LINGER, 0) }
            closer()
        }
    }
}

/** Continues a message through the rest of the gate: intercept → match&replace → script → record → forward. */
typealias CoreSink = (connectionId: Long, direction: Direction, bytes: ByteArray, forward: (ByteArray) -> Unit, forceHold: Boolean) -> Unit

/** Records a note (informational entry, excluded from the HTTP streams) in history without forwarding it. */
typealias NoteSink = (connectionId: Long, direction: Direction, bytes: ByteArray, note: String) -> Unit

/**
 * Records a REAL message (part of the direction's byte stream used by HAR / exchanges) without
 * forwarding it: a request answered locally (mock / callback / redirect) is recorded this way so
 * that request↔response pairing by order stays correct.
 */
typealias RecordSink = (connectionId: Long, direction: Direction, bytes: ByteArray) -> Unit

/** Shared daemon executors for delays and outbound (redirect / webhook) I/O. Threads time out when idle. */
object RuleExecutors {
    private val n = AtomicLong(1)
    private fun factory(prefix: String) = java.util.concurrent.ThreadFactory { r ->
        Thread(r, "expedition-rules-$prefix-${n.getAndIncrement()}").apply { isDaemon = true }
    }

    val scheduler: ScheduledExecutorService = ScheduledThreadPoolExecutor(1, factory("timer")).apply {
        setKeepAliveTime(30, TimeUnit.SECONDS); allowCoreThreadTimeOut(true); removeOnCancelPolicy = true
    }

    val io: ExecutorService = ThreadPoolExecutor(0, 32, 30, TimeUnit.SECONDS, LinkedBlockingQueue(), factory("io"))
}

/**
 * Per-connection rule sessions owned by the [expedition.pipeline.MessageGate]. Connections are
 * attached by TcpConnection (UDP is never attached and so always bypasses the rules layer).
 */
class RuleSessions(private val core: CoreSink, private val note: NoteSink, private val record: RecordSink) {
    private val controls = ConcurrentHashMap<Long, ConnectionControl>()
    private val sessions = ConcurrentHashMap<Long, HttpRuleSession>()

    fun attach(connectionId: Long, control: ConnectionControl) { controls[connectionId] = control }

    fun detach(connectionId: Long) {
        controls.remove(connectionId)
        sessions.remove(connectionId)?.close()
    }

    fun activeSessions(): Int = sessions.size

    /** Returns false when the connection is not attached (the caller then runs the plain gate). */
    fun process(engine: RulesEngine, connectionId: Long, direction: Direction, bytes: ByteArray, forward: (ByteArray) -> Unit): Boolean {
        val control = controls[connectionId] ?: return false
        val session = sessions.computeIfAbsent(connectionId) { HttpRuleSession(it, engine, control, core, note, record) }
        if (direction == Direction.CLIENT_TO_UPSTREAM) session.onClient(bytes, forward) else session.onUpstream(bytes, forward)
        return true
    }
}

/**
 * HTTP/1.x rules state machine for one TCP connection (plaintext, or decrypted by TLS MITM).
 *
 * Requests are parsed as they stream in. While no rule is active the bytes are forwarded exactly
 * as read (observe mode: only message boundaries are tracked). With active rules, a request
 * whose header block could match is buffered until complete, evaluated, and then forwarded,
 * transformed, answered locally (mock: NEVER sent upstream), redirected, delayed, held, dropped
 * or the connection is closed/reset. Every request gets a response "slot" so responses —
 * upstream, mocked or redirected — reach the client strictly in request order (keep-alive and
 * pipelining safe). After `101 Switching Protocols` / CONNECT, or on anything that is not
 * HTTP/1.x, the connection falls back to raw relay for good.
 *
 * All state is guarded by `this`; core (gate) calls are made under the lock so the per-stream
 * intercept FIFO sees messages in wire order.
 */
internal class HttpRuleSession(
    private val id: Long,
    private val engine: RulesEngine,
    private val control: ConnectionControl,
    private val core: CoreSink,
    private val note: NoteSink,
    private val record: RecordSink,
) {
    private class Piece(var bytes: ByteArray, val hold: Boolean)

    private enum class Kind { PENDING, UPSTREAM, SYNTHETIC }

    private class Slot(val request: HttpHead, val observed: Boolean) {
        var kind = Kind.PENDING
        val out = ArrayDeque<Piece>()
        var complete = false
        var responseStarted = false
        val respTransforms = ArrayList<Transform>()
        var holdResponse = false

        fun add(bytes: ByteArray, hold: Boolean = false) {
            if (bytes.isEmpty()) return
            val last = out.lastOrNull()
            if (!hold && last != null && !last.hold) last.bytes = last.bytes + bytes else out.addLast(Piece(bytes, hold))
        }
    }

    private class PendingReq(val slot: Slot, var head: HttpHead, val headWire: ByteArray, var headChanged: Boolean) {
        val bodyWire = java.io.ByteArrayOutputStream()
        val body = java.io.ByteArrayOutputStream()
        fun wire(): ByteArray = headWire + bodyWire.toByteArray()
    }

    private sealed class ReqItem {
        class Raw(val bytes: ByteArray) : ReqItem()
        class Req(val p: PendingReq) : ReqItem()
    }

    private class RespBuf(val head: HttpHead, headWire: ByteArray) {
        val wire = java.io.ByteArrayOutputStream().apply { write(headWire) }
        val body = java.io.ByteArrayOutputStream()
    }

    private var closed = false
    private var bypass = false
    private val reqParser = HttpStreamParser(true)
    private val respParser = HttpStreamParser(false, { nextUpstreamSlot()?.request?.method })
    private var reqForward: (ByteArray) -> Unit = {}
    private var respForward: (ByteArray) -> Unit = control::sendToClient

    private var reqObserve = true
    private var curReq: PendingReq? = null
    private val reqQueue = ArrayDeque<ReqItem>()
    private var reqBusy = false

    private val slots = ArrayDeque<Slot>()
    private var respObserve = true
    private var curResp: Slot? = null
    private var curBuf: RespBuf? = null
    private var upgrading = false
    private var rawTail: Slot? = null

    // ── client → upstream ───────────────────────────────────────────────

    @Synchronized
    fun onClient(bytes: ByteArray, forward: (ByteArray) -> Unit) {
        if (closed) { core(id, Direction.CLIENT_TO_UPSTREAM, bytes, forward, false); return }
        reqForward = forward
        if (bypass) {
            maybeNoteBypass()
            if (reqQueue.isEmpty() && !reqBusy) core(id, Direction.CLIENT_TO_UPSTREAM, bytes, forward, false)
            else { reqQueue.addLast(ReqItem.Raw(bytes)); pumpRequests() }
            return
        }
        if (reqParser.idle && curReq == null) {
            reqObserve = !engine.hasActive(RuleDirection.REQUEST, control.listenerName) && reqQueue.isEmpty() && !reqBusy
        }
        if (reqObserve) {
            core(id, Direction.CLIENT_TO_UPSTREAM, bytes, forward, false)
            for (e in reqParser.feed(bytes)) when (e) {
                is HttpEvent.Head -> slots.addLast(Slot(e.head, observed = true).also { it.kind = Kind.UPSTREAM })
                is HttpEvent.Raw -> { goBypass(reqParser.rawReason); break }
                else -> {}
            }
            return
        }
        for (e in reqParser.feed(bytes)) {
            onRequestEvent(e)
            if (bypass) break
        }
        pumpRequests()
    }

    private fun onRequestEvent(e: HttpEvent) {
        when (e) {
            is HttpEvent.Head -> {
                val slot = Slot(e.head, observed = false)
                slots.addLast(slot)
                val ctx = ctx(e.head, null)
                val candidate = engine.rules().any {
                    it.enabled && it.matcher.direction == RuleDirection.REQUEST && !engine.exhausted(it) && it.matcher.matchesHead(ctx)
                }
                if (candidate) {
                    var head = e.head
                    var changed = false
                    if (head.header("expect")?.contains("100-continue", ignoreCase = true) == true) {
                        // We hold the body back until the request is complete: release the client now.
                        control.sendToClient(CONTINUE)
                        head = head.remove("Expect"); changed = true
                    }
                    curReq = PendingReq(slot, head, e.wire, changed)
                } else {
                    slot.kind = Kind.UPSTREAM
                    queueRaw(e.wire)
                }
            }
            is HttpEvent.Body -> {
                val c = curReq
                if (c == null) { queueRaw(e.wire); return }
                c.bodyWire.write(e.wire); c.body.write(e.data)
                if (c.bodyWire.size() > MAX_BUFFER) {
                    note(id, Direction.CLIENT_TO_UPSTREAM, ByteArray(0), "RULES: request body over $MAX_BUFFER bytes; streamed without rule evaluation")
                    c.slot.kind = Kind.UPSTREAM
                    queueRaw(c.wire())
                    curReq = null
                }
            }
            HttpEvent.End -> curReq?.let { reqQueue.addLast(ReqItem.Req(it)); curReq = null }
            is HttpEvent.Raw -> {
                curReq?.let { it.slot.kind = Kind.UPSTREAM; queueRaw(it.wire()); curReq = null }
                queueRaw(e.wire)
                goBypass(reqParser.rawReason)
            }
        }
    }

    private fun queueRaw(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        val last = reqQueue.lastOrNull()
        if (last is ReqItem.Raw) reqQueue[reqQueue.size - 1] = ReqItem.Raw(last.bytes + bytes)
        else reqQueue.addLast(ReqItem.Raw(bytes))
    }

    private fun pumpRequests() {
        while (!reqBusy && !closed) {
            when (val item = reqQueue.removeFirstOrNull() ?: break) {
                is ReqItem.Raw -> core(id, Direction.CLIENT_TO_UPSTREAM, item.bytes, reqForward, false)
                is ReqItem.Req -> { reqBusy = true; RequestDispatch(item.p).go() }
            }
        }
    }

    private fun ctx(req: HttpHead, body: ByteArray?, resp: HttpHead? = null, respBody: ByteArray? = null) =
        MatchContext(control.listenerName, id, control.upstreamHost, control.upstreamPort, req, body, resp, respBody)

    /** Runs the matching rules' actions for one complete request; may suspend (delay / webhook). */
    private inner class RequestDispatch(val p: PendingReq) {
        private val rules = engine.rules()
        private var idx = 0
        private val steps = ArrayDeque<Pair<HttpRule, RuleAction>>()
        private var head = p.head
        private var body = p.body.toByteArray()
        private var modified = false
        private var hold = false
        private val slot = p.slot

        private fun nextRule(): HttpRule? {
            while (idx < rules.size) {
                val r = rules[idx++]
                if (!r.enabled || r.matcher.direction != RuleDirection.REQUEST) continue
                if (r.matcher.matches(ctx(head, body)) && engine.tryConsume(r)) return r
            }
            return null
        }

        fun go() {
            try {
                step()
            } catch (e: Exception) {
                note(id, Direction.CLIENT_TO_UPSTREAM, ByteArray(0), "RULES ERROR: ${e.message}; request passed through")
                if (slot.kind == Kind.PENDING) passThrough() else done()
            }
        }

        private fun step() {
            while (!closed) {
                val (rule, a) = steps.removeFirstOrNull() ?: run {
                    val r = nextRule() ?: return passThrough()
                    r.actions.forEach { steps.addLast(r to it) }
                    null
                } ?: continue
                when (a) {
                    is RuleAction.TransformRequest -> { applyRequestTransform(a.transform); modified = true }
                    is RuleAction.TransformResponse -> slot.respTransforms += a.transform
                    is RuleAction.Breakpoint -> { if (a.request) hold = true; if (a.response) slot.holdResponse = true }
                    is RuleAction.Delay -> { later(delayOf(a)) { go() }; return }
                    is RuleAction.Webhook -> {
                        if (!engine.webhooksEnabled) {
                            note(id, Direction.CLIENT_TO_UPSTREAM, ByteArray(0), "RULES: webhook of '${rule.label}' skipped (webhooks disabled)")
                        } else {
                            val payload = Webhooks.payload(rule, "request", id, control, head, body, null, null, a.forwardCredentials)
                            if (!a.respond) Webhooks.fire(a, payload)
                            else {
                                RuleExecutors.io.execute {
                                    val mock = Webhooks.call(a, payload)
                                    synchronized(this@HttpRuleSession) {
                                        if (closed) return@synchronized
                                        if (mock != null) mock(rule, mock.toBytes(), "CALLBACK") else go()
                                        pumpRequests()
                                    }
                                }
                                return
                            }
                        }
                    }
                    is RuleAction.MockResponse -> return mock(rule, a.toBytes(forHead = head.method.equals("HEAD", true)), "MOCKED")
                    is RuleAction.Redirect -> return redirect(rule, a)
                    RuleAction.Timeout -> {
                        note(id, Direction.CLIENT_TO_UPSTREAM, bytes(), "TIMEOUT by rule '${rule.label}' — not sent upstream, never answered")
                        slot.kind = Kind.SYNTHETIC
                        return done()
                    }
                    RuleAction.Close, RuleAction.Reset -> {
                        val what = if (a == RuleAction.Reset) "RESET" else "CLOSED"
                        note(id, Direction.CLIENT_TO_UPSTREAM, bytes(), "$what by rule '${rule.label}' — not sent upstream")
                        slot.kind = Kind.SYNTHETIC
                        if (a == RuleAction.Reset) control.reset() else control.close()
                        return done()
                    }
                    RuleAction.PassThrough -> return passThrough()
                }
            }
        }

        private fun later(ms: Long, k: () -> Unit) {
            RuleExecutors.scheduler.schedule({
                synchronized(this@HttpRuleSession) {
                    if (closed) return@synchronized
                    k()
                    pumpRequests()
                }
            }, ms, TimeUnit.MILLISECONDS)
        }

        private fun applyRequestTransform(t: Transform) {
            t.urlRe?.let { (re, with) ->
                val parts = head.startLine.split(' ')
                if (parts.size == 3) head = head.withStartLine("${parts[0]} ${SafeRegex.replace(re, parts[1], with)} ${parts[2]}")
            }
            val (h, b) = Transforms.apply(head, body, t)
            head = h; body = b
        }

        private fun bytes(): ByteArray = when {
            modified -> Transforms.serializeRequest(head, body)
            p.headChanged -> head.toBytes() + p.bodyWire.toByteArray()
            else -> p.wire()
        }

        private fun passThrough() {
            slot.kind = Kind.UPSTREAM
            if (bypass) slot.complete = true
            core(id, Direction.CLIENT_TO_UPSTREAM, bytes(), reqForward, hold)
            done()
        }

        /**
         * The request is recorded as a real (unforwarded) message and its answer flows through the
         * slot as a real response, so both streams stay aligned for HAR / exchange pairing; the
         * note (empty bytes) only labels what happened.
         */
        private fun answeredLocally(noteText: String) {
            record(id, Direction.CLIENT_TO_UPSTREAM, bytes())
            note(id, Direction.CLIENT_TO_UPSTREAM, ByteArray(0), noteText)
        }

        private fun mock(rule: HttpRule, response: ByteArray, what: String) {
            answeredLocally("$what by rule '${rule.label}' — not sent upstream")
            slot.kind = Kind.SYNTHETIC
            slot.add(response, slot.holdResponse)
            slot.complete = true
            pumpResponses()
            done()
        }

        private fun redirect(rule: HttpRule, a: RuleAction.Redirect) {
            val uri = java.net.URI(a.url)
            val authority = uri.rawAuthority
            var h = head.withStartLine("${head.method} ${head.originTarget} ${head.version}")
            if (!a.keepHost) h = h.set("Host", authority)
            val https = uri.scheme.equals("https", true)
            val targetPort = if (uri.port > 0) uri.port else if (https) 443 else 80
            val sameOrigin = uri.host.removePrefix("[").removeSuffix("]").equals(control.upstreamHost, ignoreCase = true) && targetPort == control.upstreamPort
            var stripped = ""
            if (!sameOrigin && !a.forwardCredentials) {
                val creds = h.headers.filter { it.first.lowercase() in Webhooks.CREDENTIAL_HEADERS }.map { it.first }.distinct()
                creds.forEach { h = h.remove(it) }
                if (creds.isNotEmpty()) stripped = "; credentials NOT forwarded to another host (${creds.joinToString()}; set forwardCredentials to send them)"
            }
            val req = Transforms.serializeRequest(h.set("Connection", "close"), body, force = true)
            answeredLocally("REDIRECTED by rule '${rule.label}' to ${a.url}$stripped")
            note(id, Direction.CLIENT_TO_UPSTREAM, req, "REDIRECTED request as sent to ${a.url}")
            slot.kind = Kind.SYNTHETIC
            val method = head.method
            val holdResp = slot.holdResponse
            RuleExecutors.io.execute {
                val resp = try {
                    OutboundHttp.normalized(OutboundHttp.send(uri, req, method, insecure = a.insecureTls), method)
                } catch (e: Exception) {
                    RuleAction.MockResponse(502, null, listOf("Content-Type" to "text/plain"),
                        BodySource.Text("Expedition rule '${rule.label}': redirect to ${a.url} failed: ${e.message}")).toBytes()
                }
                synchronized(this@HttpRuleSession) {
                    if (closed) return@synchronized
                    slot.add(resp, holdResp)
                    slot.complete = true
                    pumpResponses()
                }
            }
            done()
        }

        private fun done() { reqBusy = false }
    }

    // ── upstream → client ───────────────────────────────────────────────

    private fun nextUpstreamSlot(): Slot? = slots.firstOrNull { it.kind == Kind.UPSTREAM && !it.responseStarted }

    private fun orphan(): Slot = Slot(HttpHead("GET / HTTP/1.1", emptyList()), observed = false).also {
        it.kind = Kind.UPSTREAM; it.responseStarted = true; slots.addLast(it)
    }

    @Synchronized
    fun onUpstream(bytes: ByteArray, forward: (ByteArray) -> Unit) {
        if (closed) { core(id, Direction.UPSTREAM_TO_CLIENT, bytes, forward, false); return }
        respForward = forward
        if (bypass) { bypassResponse(bytes); return }
        if (respParser.idle && curResp == null) {
            respObserve = slots.all { it.observed } && !engine.hasActive(RuleDirection.RESPONSE, control.listenerName)
        }
        if (respObserve) {
            core(id, Direction.UPSTREAM_TO_CLIENT, bytes, forward, false)
            for (e in respParser.feed(bytes)) {
                when (e) {
                    is HttpEvent.Head -> if (!e.interim) {
                        val s = nextUpstreamSlot()
                        s?.responseStarted = true
                        curResp = s
                        upgrading = isUpgrade(s?.request, e.head)
                    }
                    HttpEvent.End -> {
                        curResp?.let { slots.remove(it) }
                        curResp = null
                        if (upgrading) { enterTunnel(); break }
                    }
                    is HttpEvent.Raw -> { goBypass(respParser.rawReason); break }
                    is HttpEvent.Body -> {}
                }
            }
            pumpResponses()
            return
        }
        for (e in respParser.feed(bytes)) {
            onResponseEvent(e)
            if (bypass) break
        }
        pumpResponses()
    }

    private fun isUpgrade(req: HttpHead?, resp: HttpHead) =
        resp.status == 101 || (req?.method.equals("CONNECT", ignoreCase = true) && resp.status in 200..299)

    private fun onResponseEvent(e: HttpEvent) {
        when (e) {
            is HttpEvent.Head -> {
                if (e.interim) { (nextUpstreamSlot() ?: curResp ?: orphan()).add(e.wire); return }
                val s = nextUpstreamSlot() ?: orphan()
                s.responseStarted = true
                curResp = s
                upgrading = isUpgrade(s.request, e.head)
                val needs = !e.untilClose && !upgrading && (s.respTransforms.isNotEmpty() || s.holdResponse || responseRuleCandidate(s, e.head))
                if (needs) curBuf = RespBuf(e.head, e.wire) else s.add(e.wire)
            }
            is HttpEvent.Body -> {
                val b = curBuf
                val s = curResp ?: orphan().also { curResp = it }
                if (b == null) { s.add(e.wire); return }
                b.wire.write(e.wire); b.body.write(e.data)
                if (b.wire.size() > MAX_BUFFER) {
                    note(id, Direction.UPSTREAM_TO_CLIENT, ByteArray(0), "RULES: response over $MAX_BUFFER bytes; streamed without rule evaluation")
                    s.add(b.wire.toByteArray()); curBuf = null
                }
            }
            HttpEvent.End -> {
                val s = curResp ?: return
                val b = curBuf
                curResp = null; curBuf = null
                if (b != null) ResponseDispatch(s, b).go() else s.complete = true
                if (upgrading) enterTunnel()
            }
            is HttpEvent.Raw -> {
                curBuf?.let { b -> curResp?.add(b.wire.toByteArray()) }
                curBuf = null
                goBypass(respParser.rawReason)
                bypassResponse(e.wire)
            }
        }
    }

    private fun responseRuleCandidate(s: Slot, head: HttpHead): Boolean {
        val c = ctx(s.request, null, head, null)
        return engine.rules().any {
            it.enabled && it.matcher.direction == RuleDirection.RESPONSE && !engine.exhausted(it) && it.matcher.matchesHead(c)
        }
    }

    /** Runs response transforms (from request rules) and RESPONSE-direction rules on a buffered response. */
    private inner class ResponseDispatch(val slot: Slot, val buf: RespBuf) {
        private val rules = engine.rules()
        private var idx = 0
        private val steps = ArrayDeque<Pair<HttpRule?, RuleAction>>().apply {
            slot.respTransforms.forEach { addLast(null to RuleAction.TransformResponse(it)) }
        }
        private var head = buf.head
        private var body = buf.body.toByteArray()
        private var modified = false
        private var hold = slot.holdResponse
        private val noBody = slot.request.method.equals("HEAD", true) || head.status == 204 || head.status == 304

        private fun matchBody(): ByteArray = Transforms.decoded(head, body) ?: body

        private fun nextRule(): HttpRule? {
            while (idx < rules.size) {
                val r = rules[idx++]
                if (!r.enabled || r.matcher.direction != RuleDirection.RESPONSE) continue
                val c = ctx(slot.request, null, head, if (r.matcher.hasBodyMatcher) matchBody() else body)
                if (r.matcher.matches(c) && engine.tryConsume(r)) return r
            }
            return null
        }

        fun go() {
            try { step() } catch (e: Exception) {
                note(id, Direction.UPSTREAM_TO_CLIENT, ByteArray(0), "RULES ERROR: ${e.message}; response passed through")
                if (!slot.complete) finish(buf.wire.toByteArray())
            }
        }

        private fun step() {
            while (!closed) {
                val (rule, a) = steps.removeFirstOrNull() ?: run {
                    val r = nextRule() ?: return finish(bytes())
                    r.actions.forEach { steps.addLast(r to it) }
                    null
                } ?: continue
                val label = rule?.label ?: "request rule"
                when (a) {
                    is RuleAction.TransformResponse -> {
                        val (h, b) = Transforms.apply(head, body, a.transform)
                        head = h; body = b; modified = true
                    }
                    is RuleAction.Breakpoint -> hold = true
                    is RuleAction.Delay -> {
                        RuleExecutors.scheduler.schedule({
                            synchronized(this@HttpRuleSession) { if (!closed) { go(); pumpResponses() } }
                        }, delayOf(a), TimeUnit.MILLISECONDS)
                        return
                    }
                    is RuleAction.Webhook -> {
                        if (!engine.webhooksEnabled || rule == null) {
                            note(id, Direction.UPSTREAM_TO_CLIENT, ByteArray(0), "RULES: webhook of '$label' skipped (webhooks disabled)")
                        } else {
                            val payload = Webhooks.payload(rule, "response", id, control, slot.request, null, head, matchBody(), a.forwardCredentials)
                            if (!a.respond) Webhooks.fire(a, payload)
                            else {
                                RuleExecutors.io.execute {
                                    val mock = Webhooks.call(a, payload)
                                    synchronized(this@HttpRuleSession) {
                                        if (closed) return@synchronized
                                        if (mock != null) finish(mock.toBytes(), "CALLBACK response by rule '$label'") else go()
                                        pumpResponses()
                                    }
                                }
                                return
                            }
                        }
                    }
                    is RuleAction.MockResponse -> return finish(a.toBytes(), "upstream response REPLACED by rule '$label'")
                    RuleAction.Timeout -> {
                        note(id, Direction.UPSTREAM_TO_CLIENT, buf.wire.toByteArray(), "TIMEOUT by rule '$label' — response withheld")
                        return
                    }
                    RuleAction.Close, RuleAction.Reset -> {
                        note(id, Direction.UPSTREAM_TO_CLIENT, buf.wire.toByteArray(), "${if (a == RuleAction.Reset) "RESET" else "CLOSED"} by rule '$label' — response withheld")
                        if (a == RuleAction.Reset) control.reset() else control.close()
                        return
                    }
                    RuleAction.PassThrough -> return finish(bytes())
                    is RuleAction.TransformRequest, is RuleAction.Redirect -> {} // request-only actions
                }
            }
        }

        private fun bytes(): ByteArray = when {
            !modified -> buf.wire.toByteArray()
            noBody -> head.remove("Transfer-Encoding").toBytes()
            else -> head.withBody(body)
        }

        private fun finish(bytes: ByteArray, noteText: String? = null) {
            if (noteText != null) note(id, Direction.UPSTREAM_TO_CLIENT, buf.wire.toByteArray(), noteText)
            slot.add(bytes, hold)
            slot.complete = true
            pumpResponses()
        }
    }

    /** Emit every ready response in request order. */
    private fun pumpResponses() {
        while (true) {
            val s = slots.firstOrNull() ?: break
            while (s.out.isNotEmpty()) {
                val p = s.out.removeFirst()
                core(id, Direction.UPSTREAM_TO_CLIENT, p.bytes, respForward, p.hold)
            }
            if (s.complete) slots.removeFirst() else break
        }
    }

    // ── fallback to raw relay ───────────────────────────────────────────

    private var bypassReason: String? = null
    private var bypassNoted = false

    /**
     * Never silent: once the connection is relayed raw for a reason other than an accepted
     * upgrade, a note says so — always for ambiguous framing (smuggling guard), and for HTTP/2 /
     * non-HTTP as soon as a rule is active for this listener (also when the rule is enabled later).
     */
    private fun maybeNoteBypass() {
        val reason = bypassReason ?: return
        if (bypassNoted) return
        val ambiguous = reason.startsWith(HttpStreamParser.REASON_AMBIGUOUS)
        if (!ambiguous && !engine.hasActive(null, control.listenerName)) return
        bypassNoted = true
        val text = when {
            reason == HttpStreamParser.REASON_HTTP2 ->
                "RULES BYPASSED: HTTP/2 — HTTP rules (mock, transform, delay, timeout, breakpoint, ...) are NOT applied on this connection " +
                    "(h2 was negotiated before a rule was active; new connections are offered http/1.1 only while rules are active)"
            ambiguous -> "RULES BYPASSED: $reason — connection relayed raw from here on (request smuggling / desync guard)"
            else -> "RULES BYPASSED: $reason — connection relayed raw from here on"
        }
        note(id, Direction.CLIENT_TO_UPSTREAM, ByteArray(0), text)
    }

    private fun goBypass(reason: String? = null) {
        if (bypass) return
        bypass = true
        bypassReason = reason
        maybeNoteBypass()
        // Responses are no longer tracked: upstream slots complete as soon as their queued bytes are out.
        slots.forEach { if (it.kind == Kind.UPSTREAM && it !== curResp) it.complete = true }
        curResp?.let { s -> curBuf?.let { s.add(it.wire.toByteArray()) }; s.complete = true }
        curResp = null; curBuf = null
        pumpResponses()
    }

    private fun bypassResponse(bytes: ByteArray) {
        if (slots.isEmpty()) { core(id, Direction.UPSTREAM_TO_CLIENT, bytes, respForward, false); return }
        val tail = rawTail ?: Slot(HttpHead("GET / HTTP/1.1", emptyList()), observed = false).also {
            it.kind = Kind.UPSTREAM; it.responseStarted = true; slots.addLast(it); rawTail = it
        }
        tail.add(bytes)
        pumpResponses()
    }

    /** 101 / CONNECT accepted: everything after is an opaque tunnel. */
    private fun enterTunnel() {
        upgrading = false
        val pending = reqParser.switchToRaw()
        respParser.switchToRaw()
        if (!reqObserve && pending.isNotEmpty()) queueRaw(pending)
        goBypass()
        pumpRequests()
    }

    /** Connection closing: record (not forward) whatever is still buffered or queued. */
    @Synchronized
    fun close() {
        if (closed) return
        for (e in respParser.finish()) if (e == HttpEvent.End) curResp?.complete = true
        curReq?.let { note(id, Direction.CLIENT_TO_UPSTREAM, it.wire(), "UNSENT (connection closed while buffered by rules)") }
        reqQueue.forEach { item ->
            val b = when (item) { is ReqItem.Raw -> item.bytes; is ReqItem.Req -> item.p.wire() }
            note(id, Direction.CLIENT_TO_UPSTREAM, b, "UNSENT (connection closed while queued by rules)")
        }
        curBuf?.let { note(id, Direction.UPSTREAM_TO_CLIENT, it.wire.toByteArray(), "UNDELIVERED (connection closed while buffered by rules)") }
        slots.forEach { s -> s.out.forEach { note(id, Direction.UPSTREAM_TO_CLIENT, it.bytes, "UNDELIVERED (connection closed)") } }
        closed = true
        reqQueue.clear(); slots.clear(); curReq = null; curBuf = null
    }

    private fun delayOf(a: RuleAction.Delay): Long =
        a.ms + if (a.jitterMs > 0) java.util.concurrent.ThreadLocalRandom.current().nextLong(a.jitterMs + 1) else 0

    companion object {
        const val MAX_BUFFER = 16 * 1024 * 1024
        private val CONTINUE = "HTTP/1.1 100 Continue\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
    }
}
