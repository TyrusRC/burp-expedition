package expedition.intercept

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class InterceptControllerTest {

    @Test
    fun `forwards immediately when intercept is disabled`() {
        val controller = InterceptController()

        val future = controller.intercept("hello".toByteArray()) { _, _ -> fail("should not hold") }

        val decision = future.get(1, TimeUnit.SECONDS) as InterceptDecision.Forward
        assertArrayEquals("hello".toByteArray(), decision.bytes)
    }

    @Test
    fun `holds the message until forward is called, then delivers edited bytes`() {
        val controller = InterceptController()
        controller.setEnabled(true)
        var heldId: Long = -1

        val future = controller.intercept("hello".toByteArray()) { id, _ -> heldId = id }

        assertFalse(future.isDone)
        controller.forward(heldId, "edited".toByteArray())

        val decision = future.get(1, TimeUnit.SECONDS) as InterceptDecision.Forward
        assertArrayEquals("edited".toByteArray(), decision.bytes)
    }

    @Test
    fun `drop resolves the future with Drop`() {
        val controller = InterceptController()
        controller.setEnabled(true)
        var heldId: Long = -1

        val future = controller.intercept("hello".toByteArray()) { id, _ -> heldId = id }
        controller.drop(heldId)

        assertEquals(InterceptDecision.Drop, future.get(1, TimeUnit.SECONDS))
    }

    @Test
    fun `each held message gets a distinct id`() {
        val controller = InterceptController()
        controller.setEnabled(true)
        val ids = mutableListOf<Long>()

        controller.intercept("a".toByteArray()) { id, _ -> ids.add(id) }
        controller.intercept("b".toByteArray()) { id, _ -> ids.add(id) }

        assertEquals(2, ids.toSet().size)
    }

    // ── FIFO ordering per (connection, direction) ──────────────────────────
    private fun InterceptController.hold(key: StreamKey, payload: String, ids: MutableList<Long>, out: MutableList<String>) =
        submit(key, key.connectionId, key.direction, payload.toByteArray(), { id, _ -> ids.add(id) }) { d ->
            out.add(if (d is InterceptDecision.Forward) String(d.bytes) else "DROP")
        }

    @Test
    fun `later message forwarded first waits until earlier ones are decided`() {
        val controller = InterceptController().apply { setEnabled(true) }
        val key = StreamKey(1, "CLIENT_TO_UPSTREAM")
        val ids = mutableListOf<Long>()
        val out = mutableListOf<String>()
        listOf("m1", "m2", "m3").forEach { controller.hold(key, it, ids, out) }

        controller.forward(ids[2], "M3".toByteArray())
        controller.forward(ids[1], "M2".toByteArray())
        assertTrue(out.isEmpty(), "nothing may be released before m1")
        // decided-but-blocked messages are no longer listed as held
        assertEquals(listOf(ids[0]), controller.heldMessages().map { it.id })

        controller.forward(ids[0], "M1".toByteArray())
        assertEquals(listOf("M1", "M2", "M3"), out)
    }

    @Test
    fun `a drop in the middle does not block or reorder the rest`() {
        val controller = InterceptController().apply { setEnabled(true) }
        val key = StreamKey(1, "UPSTREAM_TO_CLIENT")
        val ids = mutableListOf<Long>()
        val out = mutableListOf<String>()
        listOf("a", "b", "c").forEach { controller.hold(key, it, ids, out) }

        controller.forward(ids[2], "c".toByteArray())
        controller.drop(ids[1])
        controller.forward(ids[0], "a".toByteArray())
        assertEquals(listOf("a", "DROP", "c"), out)
    }

    @Test
    fun `different streams do not block each other`() {
        val controller = InterceptController().apply { setEnabled(true) }
        val ids1 = mutableListOf<Long>(); val ids2 = mutableListOf<Long>()
        val out = mutableListOf<String>()
        controller.hold(StreamKey(1, "C"), "conn1", ids1, out)
        controller.hold(StreamKey(2, "C"), "conn2", ids2, out)
        controller.hold(StreamKey(1, "U"), "conn1-up", ids2, out)

        controller.forward(ids2[0], "conn2".toByteArray())
        controller.forward(ids2[1], "conn1-up".toByteArray())
        assertEquals(listOf("conn2", "conn1-up"), out)
    }

    @Test
    fun `with intercept disabled a new message cannot overtake one still being delivered`() {
        val controller = InterceptController().apply { setEnabled(true) }
        val key = StreamKey(7, "C")
        val out = Collections.synchronizedList(mutableListOf<String>())
        val inCallback = CountDownLatch(1)
        val release = CountDownLatch(1)
        var firstId = -1L
        controller.submit(key, 7, "C", "first".toByteArray(), { id, _ -> firstId = id }) {
            inCallback.countDown()
            release.await(5, TimeUnit.SECONDS)
            out.add("first")
        }
        val forwarder = Thread { controller.forward(firstId, "first".toByteArray()) }.apply { start() }
        assertTrue(inCallback.await(5, TimeUnit.SECONDS))

        controller.setEnabled(false)
        controller.submit(key, 7, "C", "second".toByteArray(), { _, _ -> fail("must not hold") }) { out.add("second") }
        assertTrue(out.isEmpty(), "second must wait for first to finish delivering")

        release.countDown()
        forwarder.join(5000)
        assertEquals(listOf("first", "second"), out.toList())
    }

    @Test
    fun `setEnabled false releases held messages with their original bytes`() {
        val controller = InterceptController().apply { setEnabled(true) }
        val f1 = controller.intercept(StreamKey(1, "C"), "one".toByteArray()) { _, _ -> }
        val f2 = controller.intercept(StreamKey(1, "C"), "two".toByteArray()) { _, _ -> }
        controller.setEnabled(false)
        assertArrayEquals("one".toByteArray(), (f1.get(1, TimeUnit.SECONDS) as InterceptDecision.Forward).bytes)
        assertArrayEquals("two".toByteArray(), (f2.get(1, TimeUnit.SECONDS) as InterceptDecision.Forward).bytes)
        assertTrue(controller.heldMessages().isEmpty())
    }

    // ── Concurrency ────────────────────────────────────────────────────────
    @Test
    fun `forwarding one stream's messages from many threads in random order preserves FIFO`() {
        val pool = Executors.newFixedThreadPool(8)
        try {
            repeat(50) {
                val controller = InterceptController().apply { setEnabled(true) }
                val key = StreamKey(1, "C")
                val n = 40
                val ids = Collections.synchronizedList(mutableListOf<Long>())
                val out = Collections.synchronizedList(mutableListOf<String>())
                (0 until n).forEach { i -> controller.hold(key, "$i", ids, out) }
                val shuffled = ids.toList().shuffled()
                val barrier = CyclicBarrier(8)
                val done = CountDownLatch(8)
                shuffled.chunked(n / 8).forEach { part ->
                    pool.submit {
                        barrier.await()
                        part.forEach { id -> controller.forward(id, "${ids.indexOf(id)}".toByteArray()) }
                        done.countDown()
                    }
                }
                assertTrue(done.await(5, TimeUnit.SECONDS))
                assertEquals((0 until n).map { "$it" }, out.toList())
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `setEnabled false racing with new intercepts never strands a message`() {
        val pool = Executors.newFixedThreadPool(4)
        try {
            repeat(300) { iter ->
                val controller = InterceptController().apply { setEnabled(true) }
                val barrier = CyclicBarrier(4)
                val futures = Collections.synchronizedList(mutableListOf<Pair<String, java.util.concurrent.CompletableFuture<InterceptDecision>>>())
                val producers = (0 until 3).map { t ->
                    pool.submit {
                        barrier.await()
                        repeat(10) { i ->
                            val payload = "t$t-$i"
                            futures += payload to controller.intercept(StreamKey(t.toLong(), "C"), payload.toByteArray()) { _, _ -> }
                        }
                    }
                }
                val toggler = pool.submit { barrier.await(); controller.setEnabled(false) }
                producers.forEach { it.get(5, TimeUnit.SECONDS) }
                toggler.get(5, TimeUnit.SECONDS)
                futures.forEach { (payload, f) ->
                    val d = f.get(2, TimeUnit.SECONDS) as InterceptDecision.Forward
                    assertEquals(payload, String(d.bytes), "iteration $iter")
                }
                assertTrue(controller.heldMessages().isEmpty())
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `per-stream order holds when decisions race with new submissions and toggle-off`() {
        val pool = Executors.newFixedThreadPool(3)
        try {
            repeat(100) {
                val controller = InterceptController().apply { setEnabled(true) }
                val key = StreamKey(5, "C")
                val ids = Collections.synchronizedList(mutableListOf<Long>())
                val out = Collections.synchronizedList(mutableListOf<String>())
                val barrier = CyclicBarrier(3)
                val producer = pool.submit {
                    barrier.await()
                    repeat(30) { i -> controller.hold(key, "$i", ids, out) }
                }
                val forwarder = pool.submit {
                    barrier.await()
                    repeat(30) { ids.toList().shuffled().forEach { id -> controller.forward(id, controller.heldBytes(id) ?: return@forEach) } }
                }
                val toggler = pool.submit { barrier.await(); Thread.yield(); controller.setEnabled(false) }
                producer.get(5, TimeUnit.SECONDS); forwarder.get(5, TimeUnit.SECONDS); toggler.get(5, TimeUnit.SECONDS)
                controller.setEnabled(false)
                assertEquals((0 until 30).map { "$it" }, out.toList())
            }
        } finally {
            pool.shutdownNow()
        }
    }
}
