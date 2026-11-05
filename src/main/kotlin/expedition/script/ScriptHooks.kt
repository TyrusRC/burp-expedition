package expedition.script

import javax.script.Compilable
import javax.script.CompiledScript
import javax.script.ScriptEngine
import javax.script.ScriptEngineManager
import javax.script.SimpleBindings

/**
 * Operator scripting hook (JSR-223). A single script transforms every forwarded message in
 * flight: it is evaluated with the bindings `bytes` (ByteArray), `direction` (String) and
 * `connectionId` (Long), and its return value replaces the message:
 *   - a byte[]  -> the replacement bytes
 *   - a String  -> its UTF-8 bytes
 *   - null / anything else -> the message is left unchanged
 *
 * SECURITY: this runs arbitrary operator-supplied code with the FULL privileges of the Burp
 * JVM — there is no sandbox, by design (same trust level as any Burp extension). Only an
 * operator who already controls the Burp process can set a script (local UI / loopback API).
 * Never wire script-setting to an untrusted input.
 *
 * Engine-agnostic: we do NOT bundle an interpreter. The engine is discovered from the host
 * classpath (Burp ships Groovy; an operator can add any JSR-223 engine). With no engine present
 * the hook is a safe no-op. Scripts are compiled once (Compilable) and re-run per message.
 *
 * Fail-safe: a runtime error in the script never drops or corrupts traffic — the original bytes
 * are forwarded unchanged and the error is exposed via [lastError].
 */
class ScriptHooks(
    engineName: String? = null,
    manager: ScriptEngineManager = ScriptEngineManager(),
) {
    private val engine: ScriptEngine? =
        if (engineName != null) manager.getEngineByName(engineName)
        else PREFERRED.firstNotNullOfOrNull { manager.getEngineByName(it) }
            ?: manager.engineFactories.firstOrNull()?.scriptEngine

    @Volatile private var compiled: CompiledScript? = null
    @Volatile var source: String? = null
        private set
    @Volatile var lastError: String? = null
        private set

    val engineAvailable: Boolean get() = engine != null

    /** Compile and install [script] (null/blank clears it). Throws if there is no engine or the script won't compile. */
    fun setScript(script: String?) {
        if (script.isNullOrBlank()) { compiled = null; source = null; lastError = null; return }
        val e = engine ?: throw IllegalStateException("no JSR-223 script engine is available")
        val c = e as? Compilable ?: throw IllegalStateException("script engine does not support compilation")
        compiled = try {
            c.compile(script)
        } catch (ex: Exception) {
            throw IllegalArgumentException("script failed to compile: ${ex.message}", ex)
        }
        source = script
        lastError = null
    }

    /** Run the installed script against [bytes]; returns the (possibly transformed) bytes, never null. */
    fun transform(connectionId: Long, direction: String, bytes: ByteArray): ByteArray {
        val c = compiled ?: return bytes
        return try {
            val bindings = SimpleBindings()
            bindings["bytes"] = bytes
            bindings["direction"] = direction
            bindings["connectionId"] = connectionId
            coerce(c.eval(bindings)) ?: bytes
        } catch (ex: Exception) {
            lastError = ex.message ?: ex.toString()
            bytes // fail safe: never drop or corrupt traffic on a script error
        }
    }

    private fun coerce(result: Any?): ByteArray? = when (result) {
        is ByteArray -> result
        is String -> result.toByteArray()
        else -> null
    }

    private companion object {
        val PREFERRED = listOf("groovy", "Groovy", "nashorn", "graal.js", "js", "javascript")
    }
}
