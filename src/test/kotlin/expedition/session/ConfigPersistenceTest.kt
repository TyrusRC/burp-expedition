package expedition.session

import expedition.dns.DnsRedirector
import expedition.engine.ListenerConfig
import expedition.engine.Socks5ListenerConfig
import expedition.engine.TlsMode
import expedition.engine.UpstreamClientAuth
import expedition.engine.UpstreamProxy
import expedition.framing.FramingSpec
import expedition.matchreplace.MatchReplaceRule
import expedition.matchreplace.MatchType
import expedition.registry.ConnectionRegistry
import expedition.registry.ConnectionSummary
import expedition.registry.Direction
import expedition.registry.Protocol
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.ByteOrder
import java.time.Instant

class ConfigPersistenceTest {

    private val full = SavedConfig(
        listeners = listOf(
            SavedListener(ListenerConfig("a", Protocol.TCP, "127.0.0.1", 8080, "h", 80,
                tlsMode = TlsMode.MITM, upstreamProxy = UpstreamProxy("p", 1080),
                framing = FramingSpec.LengthPrefix(2, 4, ByteOrder.LITTLE_ENDIAN, -2, 4096),
                tlsPassthrough = listOf("*.pin.test")), true),
            SavedListener(ListenerConfig("d", Protocol.TCP, "0.0.0.0", 25, "m", 25,
                framing = FramingSpec.Delimiter(byteArrayOf(13, 10), 999)), false),
            SavedListener(ListenerConfig("u", Protocol.UDP, "0.0.0.0", 53, "x", 53), false),
        ),
        socks5Listeners = listOf(SavedSocks5Listener(Socks5ListenerConfig("s", "127.0.0.1", 1081), true)),
        rules = listOf(
            MatchReplaceRule(1, MatchType.REGEX, "a+", "b", enabled = false, decoded = true),
            MatchReplaceRule(7, MatchType.LITERAL_BYTES, "48 65", "00"),
        ),
        script = "bytes",
        dns = DnsSettings(listOf(DnsRedirector.Rule("*.x.com", "1.2.3.4")), "9.9.9.9", 5353),
    )

    @Test
    fun `round trips every field`() {
        val r = ConfigCodec.decode(ConfigCodec.encode(full))
        assertTrue(r.warnings.isEmpty(), r.warnings.toString())
        assertEquals(full.listeners, r.config.listeners)
        assertEquals(full.socks5Listeners, r.config.socks5Listeners)
        assertEquals(full.rules, r.config.rules)
        assertEquals("bytes", r.config.script)
        assertEquals(full.dns, r.config.dns)
    }

    @Test
    fun `secrets are never written and listeners needing them are omitted`() {
        val withAuth = SavedConfig(
            listeners = listOf(SavedListener(ListenerConfig("c", Protocol.TCP, "h", 1, "u", 2,
                upstreamClientAuth = UpstreamClientAuth(File("/k.p12"), "hunter2".toCharArray())), true)),
            socks5Listeners = listOf(SavedSocks5Listener(Socks5ListenerConfig("s", "h", 3, username = "bob", password = "pw-secret"), true)),
        )
        val json = ConfigCodec.encode(withAuth)
        assertFalse(json.contains("hunter2") || json.contains("pw-secret") || json.contains("k.p12"))
        val back = ConfigCodec.decode(json).config
        assertTrue(back.listeners.isEmpty() && back.socks5Listeners.isEmpty())
        assertEquals(listOf("c", "s"), ConfigCodec.unpersistable(withAuth))
    }

    @Test
    fun `corrupt or empty data yields empty config without throwing`() {
        for (bad in listOf(null, "", "   ", "{not json", "[1,2]", "\"str\"", "{\"listeners\":5,\"rules\":{}}")) {
            val r = ConfigCodec.decode(bad)
            assertEquals(SavedConfig(), r.config, "input: $bad")
        }
        assertTrue(ConfigCodec.decode("{not json").warnings.isNotEmpty())
    }

    @Test
    fun `a bad entry is skipped but the good ones survive`() {
        val json = """{"listeners":[
            {"name":"ok","protocol":"TCP","bindHost":"h","bindPort":1,"upstreamHost":"u","upstreamPort":2},
            {"name":"badproto","protocol":"SCTP","bindHost":"h","bindPort":1,"upstreamHost":"u","upstreamPort":2},
            {"name":"badport","protocol":"TCP","bindHost":"h","bindPort":99999,"upstreamHost":"u","upstreamPort":2},
            {"name":"badframe","protocol":"TCP","bindHost":"h","bindPort":1,"upstreamHost":"u","upstreamPort":2,"framing":{"type":"length","offset":0,"size":3000}},
            "junk"],
          "rules":[{"id":1,"matchType":"REGEX","matchValue":"(","replaceValue":""},
                   {"id":2,"matchType":"LITERAL_STRING","matchValue":"x","replaceValue":"y"}],
          "dns":{"rules":[{"host":"a","ip":"1.1.1.1"},{"host":"","ip":"x"}]}}"""
        val r = ConfigCodec.decode(json)
        assertEquals(listOf("ok"), r.config.listeners.map { it.config.name })
        assertFalse(r.config.listeners[0].running)
        assertEquals(listOf(2L), r.config.rules.map { it.id })
        assertEquals(1, r.config.dns!!.rules.size)
        assertEquals(53, r.config.dns!!.port)
        assertEquals(4, r.warnings.size, r.warnings.toString())
    }

    @Test
    fun `persistence saves running flag from engine and reloads it`() {
        val store = MapConfigStore()
        var running = setOf("a")
        val p = ConfigPersistence(store, { full.rules }, { "s1" }, { running })
        p.trackListener(full.listeners[0].config)
        p.trackListener(full.listeners[1].config)
        p.trackSocks5(full.socks5Listeners[0].config)
        p.setDns(full.dns)
        p.save()

        val p2 = ConfigPersistence(store, { emptyList() }, { null }, { emptySet() })
        val loaded = p2.load().config
        assertEquals(listOf(true, false), loaded.listeners.map { it.running })
        assertFalse(loaded.socks5Listeners[0].running)
        assertEquals("s1", loaded.script)
        assertEquals(2, loaded.rules.size)

        // forgotten listeners do not come back
        p.forgetListener("a"); p.save()
        assertEquals(listOf("d"), ConfigPersistence(store, { emptyList() }, { null }, { emptySet() }).load().config.listeners.map { it.config.name })
    }

    @Test
    fun `load survives a throwing store and save swallows write errors`() {
        val bad = object : ConfigStore {
            override fun get(key: String): String? = throw IllegalStateException("boom")
            override fun set(key: String, value: String?) = throw IllegalStateException("boom")
        }
        val logs = mutableListOf<String>()
        val p = ConfigPersistence(bad, { emptyList() }, { null }, { emptySet() }, { logs += it })
        assertEquals(SavedConfig(), p.load().config)
        p.save()
        assertTrue(logs.size >= 2)
    }

    // ---- session restore ----

    private val t = Instant.ofEpochMilli(1_700_000_000_000)
    private val snap = SessionSnapshot(
        listOf(ConnectionSummary(5, "l", Protocol.TCP, "c", "u", t, t.plusMillis(9)),
               ConnectionSummary(9, "l", Protocol.UDP, "c2", "u2", t, null)),
        listOf(ProxyMessage(11, 5, Direction.CLIENT_TO_UPSTREAM, t, byteArrayOf(1, 2), null),
               ProxyMessage(12, 5, Direction.UPSTREAM_TO_CLIENT, t.plusMillis(1), byteArrayOf(3), "view"),
               ProxyMessage(13, 777, Direction.CLIENT_TO_UPSTREAM, t, byteArrayOf(4), null)), // orphan
        mapOf(5L to setOf("x"), 9L to setOf("y")),
    )

    @Test
    fun `restore brings back connections messages and tags preserving ids`() {
        val reg = ConnectionRegistry(); val tags = FlowTagStore()
        val res = SessionStore.restore(snap, reg, tags)
        assertEquals(2, res.connectionsAdded); assertEquals(2, res.messagesAdded)
        assertEquals(snap.connections, reg.allConnections())
        val m = reg.messagesFor(5)
        assertEquals(listOf(11L, 12L), m.map { it.id })
        assertEquals(Direction.UPSTREAM_TO_CLIENT, m[1].direction)
        assertEquals(t.plusMillis(1), m[1].timestamp)
        assertArrayEquals(byteArrayOf(3), m[1].rawBytes)
        assertEquals("view", m[1].dissectedView)
        assertEquals(setOf("x"), tags.tags(5))
        // live ids continue after the imported ones
        assertEquals(10L, reg.openConnection("n", Protocol.TCP, "a", "b"))
        assertEquals(13L, reg.recordMessage(10, Direction.CLIENT_TO_UPSTREAM, byteArrayOf()).id)
    }

    @Test
    fun `restoring twice does not duplicate`() {
        val reg = ConnectionRegistry(); val tags = FlowTagStore()
        SessionStore.restore(snap, reg, tags)
        val second = SessionStore.restore(snap, reg, tags)
        assertEquals(0, second.connectionsAdded); assertEquals(0, second.messagesAdded)
        assertEquals(2, reg.allConnections().size); assertEquals(2, reg.allMessages().size)
        assertEquals(setOf("x"), tags.tags(5))
    }

    @Test
    fun `id collision with different live data re-keys instead of overwriting`() {
        val reg = ConnectionRegistry(); val tags = FlowTagStore()
        val live = reg.openConnection("live", Protocol.TCP, "lc", "lu") // id 1
        reg.recordMessage(live, Direction.CLIENT_TO_UPSTREAM, byteArrayOf(9))   // msg id 1
        val clash = SessionSnapshot(
            listOf(ConnectionSummary(1, "old", Protocol.TCP, "oc", "ou", t)),
            listOf(ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, t, byteArrayOf(5))),
            mapOf(1L to setOf("old")))
        val res = SessionStore.restore(clash, reg, tags)
        val newId = res.connectionIdMap.getValue(1)
        assertNotEquals(1L, newId)
        assertEquals("live", reg.connection(1)!!.listenerName)
        assertEquals("old", reg.connection(newId)!!.listenerName)
        assertEquals(1, reg.messagesFor(1).size)
        assertArrayEquals(byteArrayOf(5), reg.messagesFor(newId).single().rawBytes)
        assertEquals(setOf("old"), tags.tags(newId))
        assertTrue(tags.tags(1).isEmpty())
        // and a second load of the same file is still a no-op
        val again = SessionStore.restore(clash, reg, tags)
        assertEquals(0, again.connectionsAdded); assertEquals(0, again.messagesAdded)
        assertEquals(2, reg.allConnections().size)
        assertEquals(2, reg.allMessages().size)
    }

    @Test
    fun `export import restore round trip through json`() {
        val json = SessionStore.export(snap)
        val reg = ConnectionRegistry()
        SessionStore.restore(SessionStore.import(json), reg, FlowTagStore())
        assertEquals(snap.connections, reg.allConnections())
        assertEquals(2, reg.allMessages().size)
    }

    // H2: opening a project must never bind a socket — restored listeners always come back stopped.
    @Test
    fun `loadForRestore returns every listener stopped and keeps the script as data`() {
        val store = MapConfigStore()
        val p = ConfigPersistence(store, { full.rules }, { "s1" }, { setOf("a", "d", full.socks5Listeners[0].config.name) })
        full.listeners.forEach { p.trackListener(it.config) }
        p.trackSocks5(full.socks5Listeners[0].config)
        p.save()
        val raw = ConfigPersistence(store, { emptyList() }, { null }, { emptySet() }).load().config
        assertTrue(raw.listeners.any { it.running }, "precondition: running flags were saved")
        val safe = ConfigPersistence(store, { emptyList() }, { null }, { emptySet() }).loadForRestore().config
        assertTrue(safe.listeners.none { it.running })
        assertTrue(safe.socks5Listeners.none { it.running })
        assertEquals("s1", safe.script)
    }

    @Test
    fun `loadForRestore returns all rules disabled with content intact`() {
        val store = MapConfigStore()
        val http = expedition.rules.HttpRule(id = 3, name = "evil", enabled = true)
        val p = ConfigPersistence(store, { full.rules }, { null }, { emptySet() }, httpRules = { listOf(http) })
        p.save()
        val c = ConfigPersistence(store, { emptyList() }, { null }, { emptySet() }).loadForRestore().config
        assertEquals(2, c.rules.size)
        assertTrue(c.rules.none { it.enabled })
        assertEquals(full.rules.map { it.matchValue }, c.rules.map { it.matchValue })
        assertEquals(1, c.httpRules.size)
        assertTrue(c.httpRules.none { it.enabled })
        assertEquals("evil", c.httpRules[0].name)
    }

    @Test
    fun `loadForRestore on corrupt data does not throw`() {
        val store = MapConfigStore(mutableMapOf(ConfigPersistence.KEY to "{not json"))
        val r = ConfigPersistence(store, { emptyList() }, { null }, { emptySet() }).loadForRestore()
        assertTrue(r.config.rules.isEmpty() && r.config.httpRules.isEmpty())
    }
}
