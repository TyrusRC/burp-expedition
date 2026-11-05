package expedition.server

import expedition.intercept.InterceptController
import expedition.matchreplace.MatchReplaceEngine
import expedition.registry.ConnectionRegistry
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * stop() must release the HttpServer's worker thread pool. HttpServer.stop() does NOT shut down
 * an application-supplied executor (JDK contract), so a leaked fixed pool keeps non-daemon threads
 * alive and pins the extension classloader across Burp unload/reload — a BApp Store rejection.
 */
class ControlApiServerLifecycleTest {

    private fun liveApiThreads(): Int =
        Thread.getAllStackTraces().keys.count { it.isAlive && it.name.startsWith("expedition-ctrl-api") }

    @Test
    fun `stop releases the control-API thread pool`() {
        val baseline = liveApiThreads()
        val port = ServerSocket(0).use { it.localPort }
        val server = ControlApiServer(
            host = "127.0.0.1", port = port,
            registry = ConnectionRegistry(), matchReplace = MatchReplaceEngine(),
            intercept = InterceptController(),
            startListener = {}, stopListener = {}, runningListeners = { emptySet() },
        )
        server.start()
        // Fire a request so the lazy fixed pool actually spins up at least one worker thread.
        HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port/status")).build(),
            HttpResponse.BodyHandlers.ofString())
        assertTrue(liveApiThreads() > baseline, "precondition: the server should have started worker threads")

        server.stop()

        // Pool shutdown + thread death is asynchronous; poll briefly.
        val deadline = System.currentTimeMillis() + 3000
        while (liveApiThreads() > baseline && System.currentTimeMillis() < deadline) Thread.sleep(25)
        assertTrue(liveApiThreads() <= baseline,
            "control-API worker threads survived stop() — the executor was not shut down (leak)")
    }
}
