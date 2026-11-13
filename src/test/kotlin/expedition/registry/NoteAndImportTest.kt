package expedition.registry

import expedition.analysis.HttpExchanges
import expedition.export.HarCodec
import expedition.rules.RuleFromTraffic
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NoteAndImportTest {
    @Test
    fun `import enforces byte budget and counter never negative`() {
        val src = ConnectionRegistry()
        val c = src.openConnection("l", Protocol.TCP, "c", "u")
        repeat(5) { src.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, ByteArray(4) { i -> (it * 10 + i).toByte() }) }
        val dst = ConnectionRegistry(maxBytes = 10)
        repeat(3) { dst.importSnapshot(src.allConnections(), src.allMessages()) }
        assertTrue(dst.retainedMessageBytes() in 0..10)
        assertEquals(dst.allMessages().sumOf { it.rawBytes.size.toLong() }, dst.retainedMessageBytes())
        dst.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, ByteArray(20))
        assertTrue(dst.retainedMessageBytes() >= 0)
    }

    @Test
    fun `notes between request and response do not break pairing`() {
        val r = ConnectionRegistry()
        val c = r.openConnection("l", Protocol.TCP, "c", "example.com:9443")
        r.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        r.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray(), "REPLACED by rule")
        r.recordMessage(c, Direction.UPSTREAM_TO_CLIENT, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
        val msgs = r.messagesFor(c)
        assertEquals(1, HttpExchanges.extract(c, msgs).size)
        assertEquals(1, RuleFromTraffic.exchanges(msgs).size)
        assertEquals(1, HarCodec.export(r, c).entries)
        r.markTls(c)
        assertTrue(r.connection(c)!!.tls)
    }

    @Test
    fun `importing many messages with colliding ids is fast and still idempotent`() {
        val src = ConnectionRegistry(maxMessages = 100_000)
        val c = src.openConnection("l", Protocol.TCP, "c", "u")
        repeat(20_000) { src.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, "m$it".toByteArray()) }
        val dst = ConnectionRegistry(maxMessages = 100_000)
        val d = dst.openConnection("l", Protocol.TCP, "c", "u")
        repeat(5_000) { dst.recordMessage(d, Direction.CLIENT_TO_UPSTREAM, "other$it".toByteArray()) }
        val start = System.nanoTime()
        val first = dst.importSnapshot(src.allConnections(), src.allMessages())
        val second = dst.importSnapshot(src.allConnections(), src.allMessages())
        val seconds = (System.nanoTime() - start) / 1e9
        assertTrue(seconds < 10, "import took $seconds s")
        assertEquals(20_000, first.messagesAdded)
        assertEquals(0, second.messagesAdded)
        assertEquals(25_000, dst.allMessages().size)
    }
}

class ConcurrentImportTest {
    @Test
    fun `large import concurrent with live writes loses nothing and duplicates nothing`() {
        val src = ConnectionRegistry(maxMessages = 100_000, maxBytes = Long.MAX_VALUE / 4)
        val c = src.openConnection("l", Protocol.TCP, "c", "u")
        repeat(20_000) { src.recordMessage(c, Direction.CLIENT_TO_UPSTREAM, "m$it".toByteArray()) }
        val dst = ConnectionRegistry(maxMessages = 100_000, maxBytes = Long.MAX_VALUE / 4)
        val live = dst.openConnection("live", Protocol.TCP, "c", "u")
        val stop = java.util.concurrent.atomic.AtomicBoolean(false)
        val written = java.util.concurrent.atomic.AtomicInteger()
        val t = Thread { while (!stop.get()) { dst.recordMessage(live, Direction.UPSTREAM_TO_CLIENT, "live${written.get()}".toByteArray()); written.incrementAndGet() } }
        t.start()
        val res = dst.importSnapshot(src.allConnections(), src.allMessages())
        stop.set(true); t.join()
        assertEquals(20_000, res.messagesAdded)
        assertEquals(20_000 + written.get(), dst.allMessages().size)
        assertEquals(dst.allMessages().size, dst.allMessages().map { it.id }.toSet().size)
        // idempotent
        assertEquals(0, dst.importSnapshot(src.allConnections(), src.allMessages()).messagesAdded)
    }
}
