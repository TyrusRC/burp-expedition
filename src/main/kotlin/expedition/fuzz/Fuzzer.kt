package expedition.fuzz

import expedition.registry.Protocol
import expedition.ui.ReplaySender

/**
 * Replays a seed payload with mutations against a TCP/UDP target, collecting each mutated
 * request and the response it drew — the raw-socket analogue of Burp Intruder. Reuses
 * [ReplaySender] for the actual send/receive.
 *
 * NOTE: sequential (one case at a time), bounded by [iterations]; intended for targets the
 * user controls. No throttling — respect the target's limits when choosing iteration counts.
 */
class Fuzzer(private val sender: ReplaySender = ReplaySender()) {

    data class Case(val input: ByteArray, val response: ByteArray)

    fun fuzz(
        protocol: Protocol,
        host: String,
        port: Int,
        seed: ByteArray,
        iterations: Int,
        mutator: ByteMutator,
        timeoutMillis: Long = 2000
    ): List<Case> = (0 until iterations).map {
        val input = mutator.mutate(seed)
        Case(input, sender.replay(protocol, host, port, input, timeoutMillis))
    }
}
