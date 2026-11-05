package expedition.dissector

import expedition.registry.Direction
import expedition.registry.ProxyMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

private fun ldapMsg(bytes: ByteArray) = ProxyMessage(1, 1, Direction.CLIENT_TO_UPSTREAM, Instant.now(), bytes)

class LdapDissectorTest {

    private val d = LdapDissector()

    // LDAPMessage SEQUENCE { messageID INTEGER (1), bindRequest [APPLICATION 0] { version 3, name "dc=com", simple "" } }
    //   30 12                                  SEQUENCE, len 18
    //     02 01 01                             messageID = 1
    //     60 0D                                bindRequest [APPLICATION 0], len 13
    //       02 01 03                           version = 3
    //       04 06 64 63 3d 63 6f 6d            name = "dc=com"
    //       80 00                              simple authentication [0], empty
    private val bindRequest = byteArrayOf(
        0x30, 0x12,
        0x02, 0x01, 0x01,
        0x60, 0x0D,
        0x02, 0x01, 0x03,
        0x04, 0x06, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
        0x80.toByte(), 0x00,
    )

    // LDAPMessage SEQUENCE { messageID INTEGER (2), searchResultDone [APPLICATION 5] { success, "", "" } }
    //   30 0C                                  SEQUENCE, len 12
    //     02 01 02                             messageID = 2
    //     65 07                                searchResultDone [APPLICATION 5], len 7
    //       0A 01 00                           resultCode = success (ENUMERATED)
    //       04 00                              matchedDN = ""
    //       04 00                              diagnosticMessage = ""
    private val searchResultDone = byteArrayOf(
        0x30, 0x0C,
        0x02, 0x01, 0x02,
        0x65, 0x07,
        0x0A, 0x01, 0x00,
        0x04, 0x00,
        0x04, 0x00,
    )

    @Test
    fun `supports a valid LDAP bindRequest`() {
        assertTrue(d.supports(ldapMsg(bindRequest)))
    }

    @Test
    fun `supports a valid LDAP searchResultDone`() {
        assertTrue(d.supports(ldapMsg(searchResultDone)))
    }

    @Test
    fun `rejects non-LDAP data`() {
        assertFalse(d.supports(ldapMsg(byteArrayOf(0x12, 0x34, 0x56, 0x78))))
        assertFalse(d.supports(ldapMsg(byteArrayOf())))
        assertFalse(d.supports(ldapMsg("+PONG\r\n".toByteArray())))
    }

    @Test
    fun `rejects a SEQUENCE whose protocolOp is not an LDAP operation`() {
        // 30 06  02 01 01  04 01 41  -- valid SEQUENCE+INTEGER, but op tag 0x04 is not an LDAP op
        val notLdap = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x41)
        assertFalse(d.supports(ldapMsg(notLdap)))
    }

    @Test
    fun `renders bindRequest with op name and messageID`() {
        val out = d.render(ldapMsg(bindRequest))
        assertTrue(out.contains("LDAP"), out)
        assertTrue(out.contains("bindRequest"), out)
        assertTrue(out.contains("messageID=1"), out)
    }

    @Test
    fun `round-trips through render and parseEdit`() {
        val original = ldapMsg(bindRequest)
        val rendered = d.render(original)
        val rebuilt = d.parseEdit(rendered, original)
        assertArrayEquals(bindRequest, rebuilt, "round-trip failed")
    }
}
