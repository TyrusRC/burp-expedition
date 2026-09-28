package expedition.ui

import expedition.registry.Protocol
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket

class ReplaySender {
    fun replay(protocol: Protocol, host: String, port: Int, bytes: ByteArray, timeoutMillis: Long = 2000): ByteArray = when (protocol) {
        Protocol.TCP -> replayTcp(host, port, bytes, timeoutMillis)
        Protocol.UDP -> replayUdp(host, port, bytes, timeoutMillis)
    }

    private fun replayTcp(host: String, port: Int, bytes: ByteArray, timeoutMillis: Long): ByteArray {
        // Bound the connect itself: Socket(host, port) blocks until the OS SYN timeout
        // (tens of seconds) on a dead/filtered upstream, and a refused connection throws.
        // Both would otherwise propagate to the caller (the Swing EDT) — freeze or crash.
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMillis.toInt())
                socket.soTimeout = timeoutMillis.toInt()
                socket.getOutputStream().write(bytes)
                socket.getOutputStream().flush()
                socket.getInputStream().readUntilIdle(timeoutMillis.toInt())
            }
        } catch (e: java.io.IOException) {
            ByteArray(0)
        }
    }

    private fun replayUdp(host: String, port: Int, bytes: ByteArray, timeoutMillis: Long): ByteArray {
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMillis.toInt()
            socket.send(DatagramPacket(bytes, bytes.size, InetSocketAddress(host, port)))
            val buffer = ByteArray(4096)
            val packet = DatagramPacket(buffer, buffer.size)
            return try {
                socket.receive(packet)
                buffer.copyOf(packet.length)
            } catch (e: java.io.IOException) {
                ByteArray(0)
            }
        }
    }

    /** Read until the peer goes idle (soTimeout) or closes, so a multi-segment
     *  response isn't truncated to the first packet. Bounded to 1 MiB so a chatty
     *  or streaming upstream can't grow the buffer without limit. */
    private fun java.io.InputStream.readUntilIdle(soTimeoutMillis: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        val cap = 1 shl 20
        try {
            while (out.size() < cap) {
                val read = this.read(chunk)
                if (read <= 0) break
                out.write(chunk, 0, read)
            }
        } catch (_: java.net.SocketTimeoutException) {
            // idle window elapsed with nothing more to read — return what we have.
        }
        return out.toByteArray()
    }
}
