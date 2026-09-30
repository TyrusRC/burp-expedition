package expedition.fuzz

import kotlin.random.Random

/**
 * Mutates a seed payload for fuzzing. One random mutation per call, deterministic for a
 * given [Random] so runs are reproducible. Size grows by at most one byte per mutation.
 */
class ByteMutator(private val random: Random) {

    fun mutate(seed: ByteArray): ByteArray {
        if (seed.isEmpty()) return byteArrayOf(random.nextInt(256).toByte())
        return when (random.nextInt(4)) {
            0 -> seed.copyOf().also { val i = random.nextInt(it.size); it[i] = (it[i].toInt() xor (1 shl random.nextInt(8))).toByte() } // bit flip
            1 -> seed.copyOf().also { it[random.nextInt(it.size)] = random.nextInt(256).toByte() }                                     // byte set
            2 -> seed + byteArrayOf(random.nextInt(256).toByte())                                                                     // append
            else -> if (seed.size > 1) seed.copyOf(seed.size - 1) else seed.copyOf()                                                  // truncate
        }
    }
}
