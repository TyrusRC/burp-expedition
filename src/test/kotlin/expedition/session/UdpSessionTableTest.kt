package expedition.session

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant

class UdpSessionTableTest {

    @Test
    fun `creates a new session on first lookup for a client address`() {
        val table = UdpSessionTable<String>(Duration.ofMinutes(1))
        val address = InetSocketAddress("127.0.0.1", 1234)
        var created = 0

        val value = table.sessionFor(address) { created++; "session-$created" }

        assertEquals("session-1", value)
        assertEquals(1, created)
        assertEquals(1, table.size())
    }

    @Test
    fun `reuses the existing session for the same client address`() {
        val table = UdpSessionTable<String>(Duration.ofMinutes(1))
        val address = InetSocketAddress("127.0.0.1", 1234)
        var created = 0

        table.sessionFor(address) { created++; "session-$created" }
        val second = table.sessionFor(address) { created++; "session-$created" }

        assertEquals("session-1", second)
        assertEquals(1, created)
    }

    @Test
    fun `evictIdle removes sessions older than the idle timeout and reports them`() {
        var now = Instant.parse("2026-01-01T00:00:00Z")
        val table = UdpSessionTable<String>(Duration.ofSeconds(30)) { now }
        val address = InetSocketAddress("127.0.0.1", 1234)
        table.sessionFor(address) { "session" }

        now = now.plusSeconds(31)
        val evicted = mutableListOf<InetSocketAddress>()
        table.evictIdle { addr, _ -> evicted.add(addr) }

        assertEquals(listOf(address), evicted)
        assertEquals(0, table.size())
    }

    @Test
    fun `evictIdle keeps sessions accessed within the idle timeout`() {
        var now = Instant.parse("2026-01-01T00:00:00Z")
        val table = UdpSessionTable<String>(Duration.ofSeconds(30)) { now }
        val address = InetSocketAddress("127.0.0.1", 1234)
        table.sessionFor(address) { "session" }

        now = now.plusSeconds(10)
        table.sessionFor(address) { "should-not-be-called" }
        now = now.plusSeconds(25)
        val evicted = mutableListOf<InetSocketAddress>()
        table.evictIdle { addr, _ -> evicted.add(addr) }

        assertTrue(evicted.isEmpty())
        assertEquals(1, table.size())
    }

    @Test
    fun `drainAll removes every session regardless of age`() {
        val table = UdpSessionTable<String>(Duration.ofMinutes(10))
        table.sessionFor(InetSocketAddress("127.0.0.1", 1)) { "a" }
        table.sessionFor(InetSocketAddress("127.0.0.1", 2)) { "b" }

        val drained = mutableListOf<String>()
        table.drainAll { _, value -> drained.add(value) }

        assertEquals(setOf("a", "b"), drained.toSet())
        assertEquals(0, table.size())
    }
}
