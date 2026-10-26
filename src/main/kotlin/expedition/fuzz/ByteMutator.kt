package expedition.fuzz

import kotlin.random.Random

/**
 * Mutates a seed payload for fuzzing. One random mutation per call, deterministic for a
 * given [Random] so runs are reproducible.
 */
class ByteMutator(private val random: Random) {

    private val boundaryValues = byteArrayOf(0x00, 0xFF.toByte(), 0x7F, 0x80.toByte(), 0x0A, 0x0D)

    fun mutate(seed: ByteArray): ByteArray {
        if (seed.isEmpty()) return byteArrayOf(random.nextInt(256).toByte())
        return when (random.nextInt(8)) {
            0 -> seed.copyOf().also { val i = random.nextInt(it.size); it[i] = (it[i].toInt() xor (1 shl random.nextInt(8))).toByte() } // bit flip
            1 -> seed.copyOf().also { it[random.nextInt(it.size)] = random.nextInt(256).toByte() }                                     // byte set
            2 -> seed + byteArrayOf(random.nextInt(256).toByte())                                                                     // append
            3 -> if (seed.size > 1) seed.copyOf(seed.size - 1) else seed.copyOf()                                                    // truncate
            4 -> { // insert at offset
                val pos = random.nextInt(seed.size + 1)
                val out = ByteArray(seed.size + 1)
                seed.copyInto(out, 0, 0, pos)
                out[pos] = random.nextInt(256).toByte()
                seed.copyInto(out, pos + 1, pos, seed.size)
                out
            }
            5 -> { // repeat block
                val blockLen = random.nextInt(1, minOf(5, seed.size + 1))
                val start = random.nextInt(seed.size - blockLen + 1)
                val block = seed.sliceArray(start until start + blockLen)
                val reps = random.nextInt(2, 5)
                val repeated = ByteArray(block.size * reps) { block[it % block.size] }
                seed.sliceArray(0 until start) + repeated + seed.sliceArray(start + blockLen until seed.size)
            }
            6 -> seed.copyOf().also { it[random.nextInt(it.size)] = boundaryValues[random.nextInt(boundaryValues.size)] } // boundary value
            else -> { // swap adjacent
                if (seed.size < 2) seed.copyOf()
                else seed.copyOf().also {
                    val i = random.nextInt(it.size - 1)
                    val tmp = it[i]; it[i] = it[i + 1]; it[i + 1] = tmp
                }
            }
        }
    }
}
