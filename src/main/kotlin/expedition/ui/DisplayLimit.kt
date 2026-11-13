package expedition.ui

import java.util.concurrent.Executors
import java.util.concurrent.ExecutorService

/** Pure helpers keeping the Swing EDT free of heavy work and large strings. */
object DisplayLimit {
    const val MAX_CHARS = 256 * 1024

    /** Result of [truncate]; [truncated] means the shown text is NOT the full content. */
    data class Shown(val text: String, val truncated: Boolean)

    fun truncate(text: String, maxChars: Int = MAX_CHARS, totalBytes: Int = text.length): Shown =
        if (text.length <= maxChars) Shown(text, false)
        else Shown(text.substring(0, maxChars) + "\n... truncated, $totalBytes bytes total (use Export Session / the control API for the full message)", true)

    /** Appends parts until [maxChars] is reached; stops early so huge histories are never fully joined. */
    fun joinBounded(parts: Sequence<String>, maxChars: Int = MAX_CHARS): Shown {
        val sb = StringBuilder()
        var n = 0
        for (p in parts) {
            n++
            if (sb.length + p.length + 1 > maxChars) {
                val room = maxChars - sb.length
                if (room > 0) sb.append(p.take(room))
                sb.append("\n... truncated after $n message(s) (use Export Session for the full history)")
                return Shown(sb.toString(), true)
            }
            if (sb.isNotEmpty()) sb.append('\n')
            sb.append(p)
        }
        return Shown(sb.toString(), false)
    }

    /** Single shared daemon worker for UI-triggered blocking work (forward, replay, render). */
    val worker: ExecutorService = Executors.newFixedThreadPool(2) { r ->
        Thread(r, "expedition-ui-worker").apply { isDaemon = true }
    }

    /**
     * Dedicated single-thread executor for intercept on/off toggles: strictly sequential so a quick
     * on-then-off can never be reordered, and independent of [worker] so a slow replay cannot delay it.
     */
    val interceptWorker: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "expedition-intercept-worker").apply { isDaemon = true }
    }

    /**
     * Applies [enabled] on [executor] and then reports the controller's REAL state to [onResult]
     * (so a UI checkbox mirrors what is actually active, not what was last clicked).
     */
    fun toggleIntercept(
        executor: java.util.concurrent.Executor,
        controller: expedition.intercept.InterceptController,
        enabled: Boolean,
        onResult: (Boolean) -> Unit,
    ) {
        executor.execute {
            try { controller.setEnabled(enabled) } catch (_: Exception) { }
            onResult(controller.isEnabled())
        }
    }
}
