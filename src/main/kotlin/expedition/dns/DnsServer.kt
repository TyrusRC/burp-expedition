package expedition.dns

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Minimal UDP DNS server: receives queries and replies with whatever [DnsRedirector] decides.
 * A single daemon receive-loop thread; stop() closes the socket (unblocking the loop) and joins,
 * so Burp can unload the extension without leaking the thread or the port.
 *
 * Binding the privileged port 53 needs root/admin or a capability; pass any other port and point
 * the target's resolver at it otherwise. Port 0 binds an ephemeral port (used by tests).
 *
 * NOTE: one datagram = one message, 4 KiB receive buffer (covers EDNS0). TCP DNS and messages
 * larger than the buffer are out of scope.
 */
class DnsServer(
    private val host: String,
    private val port: Int,
    private val redirector: DnsRedirector,
    private val onError: (String) -> Unit = {},
) {
    private var socket: DatagramSocket? = null
    private var thread: Thread? = null
    @Volatile private var running = false

    fun start() {
        val s = DatagramSocket(port, InetAddress.getByName(host))
        socket = s
        running = true
        thread = Thread({ loop(s) }, "expedition-dns-$port").apply { isDaemon = true; start() }
    }

    /** The actual bound port (useful when started on port 0). */
    fun boundPort(): Int = socket?.localPort ?: port

    private fun loop(s: DatagramSocket) {
        val buf = ByteArray(4096)
        while (running) {
            try {
                val packet = DatagramPacket(buf, buf.size)
                s.receive(packet)
                val query = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                val reply = redirector.respond(query) ?: continue
                s.send(DatagramPacket(reply, reply.size, packet.socketAddress))
            } catch (e: Exception) {
                if (running) onError(e.message ?: "DNS server error")
                // socket closed by stop() → loop condition ends
            }
        }
    }

    fun stop() {
        running = false
        socket?.close()
        socket = null
        thread?.join(2000)
        thread = null
    }
}
