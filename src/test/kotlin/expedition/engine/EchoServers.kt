package expedition.engine

import java.net.ServerSocket
import java.net.Socket

class TcpEchoServer : AutoCloseable {
    private val serverSocket = ServerSocket(0)
    val port: Int get() = serverSocket.localPort
    @Volatile private var running = true
    private val thread = Thread {
        while (running) {
            val client: Socket = try { serverSocket.accept() } catch (e: Exception) { break }
            Thread {
                client.use { s ->
                    val input = s.getInputStream()
                    val output = s.getOutputStream()
                    val buffer = ByteArray(4096)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        output.flush()
                    }
                }
            }.start()
        }
    }.apply { isDaemon = true; start() }

    override fun close() {
        running = false
        serverSocket.close()
    }
}
