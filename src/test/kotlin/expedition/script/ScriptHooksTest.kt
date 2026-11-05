package expedition.script

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Groovy is on the TEST classpath, so a real JSR-223 engine is discoverable here. */
class ScriptHooksTest {

    private fun hooks() = ScriptHooks() // default: discover an available engine (groovy in tests)

    @Test fun `an engine is discovered when one is on the classpath`() {
        assertTrue(hooks().engineAvailable)
    }

    @Test fun `with no script set, transform passes bytes through unchanged`() {
        val h = hooks()
        val input = "hello".toByteArray()
        assertEquals("hello", String(h.transform(1, "CLIENT_TO_UPSTREAM", input)))
    }

    @Test fun `a script transforms the bytes`() {
        val h = hooks()
        h.setScript("new String(bytes).toUpperCase().getBytes()")
        assertEquals("HELLO", String(h.transform(1, "CLIENT_TO_UPSTREAM", "hello".toByteArray())))
    }

    @Test fun `the script can read the direction and connection bindings`() {
        val h = hooks()
        h.setScript("(direction + ':' + connectionId).getBytes()")
        assertEquals("UPSTREAM_TO_CLIENT:42", String(h.transform(42, "UPSTREAM_TO_CLIENT", "x".toByteArray())))
    }

    @Test fun `returning null leaves the bytes unchanged`() {
        val h = hooks()
        h.setScript("if (new String(bytes) == 'keep') return null; return 'changed'.getBytes()")
        assertEquals("keep", String(h.transform(1, "CLIENT_TO_UPSTREAM", "keep".toByteArray())))
        assertEquals("changed", String(h.transform(1, "CLIENT_TO_UPSTREAM", "other".toByteArray())))
    }

    @Test fun `an invalid script is rejected at set time and not installed`() {
        val h = hooks()
        assertThrows(IllegalArgumentException::class.java) { h.setScript("this is ((( not groovy") }
        // the bad script must not have been installed — transform still passes through
        assertEquals("ok", String(h.transform(1, "CLIENT_TO_UPSTREAM", "ok".toByteArray())))
    }

    @Test fun `a runtime error in the script fails safe (bytes unchanged) and is recorded`() {
        val h = hooks()
        h.setScript("throw new RuntimeException('boom')")
        val input = "data".toByteArray()
        assertEquals("data", String(h.transform(1, "CLIENT_TO_UPSTREAM", input)), "fail-safe passthrough")
        assertNotNull(h.lastError)
        assertTrue(h.lastError!!.contains("boom"), h.lastError!!)
    }

    @Test fun `clearing the script restores passthrough`() {
        val h = hooks()
        h.setScript("'X'.getBytes()")
        assertEquals("X", String(h.transform(1, "CLIENT_TO_UPSTREAM", "y".toByteArray())))
        h.setScript(null)
        assertEquals("y", String(h.transform(1, "CLIENT_TO_UPSTREAM", "y".toByteArray())))
    }

    @Test fun `no engine available means not available and passthrough`() {
        val h = ScriptHooks(engineName = "no-such-engine-xyz")
        assertFalse(h.engineAvailable)
        assertEquals("z", String(h.transform(1, "CLIENT_TO_UPSTREAM", "z".toByteArray())))
        assertThrows(IllegalStateException::class.java) { h.setScript("'a'.getBytes()") }
    }
}
