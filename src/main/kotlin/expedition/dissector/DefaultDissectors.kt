package expedition.dissector

/**
 * The default dissector line-up, in one testable place (see DefaultDissectorsTest) instead
 * of inlined in ExpeditionExtension where it can't be exercised without Burp.
 *
 * register() inserts at index 0, so the LAST registered is tried FIRST. The list is therefore
 * ordered by SIGNATURE SPECIFICITY: register the loosest heuristics first (lowest priority) and
 * the strongest signatures last (highest priority). This matters because several protocols have
 * deliberately loose supports():
 *   - Kafka has no magic at all (only a self-consistent length prefix + plausible field ranges).
 *   - QUIC short-header packets are almost indistinguishable from random bytes (one header bit).
 *   - Protobuf is a byte heuristic; MQTT's 1-byte fixed header (0x30) collides with e.g. an LDAP
 *     SEQUENCE (also 0x30) and a bare line of text.
 * Putting those last-resort matchers below the magic/structured ones (TLS 0x16, SMB2 'FE SMB',
 * STUN magic cookie, AMQP header/0xCE framing, LDAP BER+op-tag, DNS, Redis RESP) stops them from
 * mis-claiming traffic that a specific dissector would decode correctly.
 */
fun defaultDissectors(): DissectorRegistry = DissectorRegistry().apply {
    // ── Last-resort heuristics (lowest priority) ──────────────────────────────
    register(KafkaDissector())          // no magic bytes
    register(ProtobufDissector())       // byte heuristic
    register(QuicDissector())           // short-header ≈ any byte with the fixed bit
    register(MqttDissector())           // 1-byte fixed header collides with 0x30/text
    register(LineProtocolDissector())   // any text line
    // ── Structured binary protocols ───────────────────────────────────────────
    register(Http2FrameDissector())
    register(WebSocketDissector())
    register(MysqlDissector())
    register(PostgresDissector())
    register(MongoDissector())
    register(Dnp3Dissector())
    register(ModbusDissector())
    register(DnsDissector())
    // ── Strong signatures (highest priority) ──────────────────────────────────
    register(LdapDissector())           // BER SEQUENCE + INTEGER + known op tag
    register(AmqpDissector())           // protocol header or 0xCE-terminated frame
    register(StunDissector())           // magic cookie 0x2112A442
    register(Smb2Dissector())           // magic 0xFE 'S' 'M' 'B'
    register(TlsDissector())            // 0x16 + version + handshake type
    register(RedisDissector())          // RESP markers; recognise text before binary heuristics
}
