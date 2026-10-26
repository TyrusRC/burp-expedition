package expedition.fuzz

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import kotlin.random.Random

class ByteMutatorTest {

    @Test
    fun `is deterministic for a given seed`() {
        val seed = "AAAisis".toByteArray()
        val a = ByteMutator(Random(42)).mutate(seed)
        val b = ByteMutator(Random(42)).mutate(seed)
        assertArrayEquals(a, b)
    }

    @Test
    fun `usually changes the input`() {
        val seed = "hello world".toByteArray()
        val mutator = ByteMutator(Random(7))
        var changed = 0
        repeat(50) { if (!mutator.mutate(seed).contentEquals(seed)) changed++ }
        assertTrue(changed > 40, "expected most mutations to change the input, got $changed/50")
    }

    @Test
    fun `handles an empty seed without crashing`() {
        val out = ByteMutator(Random(1)).mutate(ByteArray(0))
        assertNotNull(out)
    }

    @Test
    fun `growth is bounded per mutation`() {
        val seed = ByteArray(10)
        val mutator = ByteMutator(Random(3))
        // repeat-block can grow by up to blockLen*(reps-1) where blockLen<=4, reps<=4 => +12
        repeat(200) { assertTrue(mutator.mutate(seed).size <= seed.size + 16,
            "mutation grew beyond reasonable bound") }
    }

    @Test
    fun `all 8 strategies produce non-null output`() {
        // Run enough iterations with a fixed seed that all 8 branches are hit.
        val seed = "ABCDEFGHIJ".toByteArray()
        val mutator = ByteMutator(Random(0))
        val sizes = mutableSetOf<Int>()
        val outputs = mutableListOf<ByteArray>()
        repeat(1000) {
            val out = mutator.mutate(seed)
            assertNotNull(out)
            assertTrue(out.isNotEmpty(), "mutation produced empty output from non-empty seed")
            sizes.add(out.size)
            outputs.add(out)
        }
        // With 8 strategies over 1000 runs, we expect size variety:
        // truncate (9), same-size (10), append/insert (11), repeat-block (variable)
        assertTrue(sizes.size >= 3, "expected size variety from 8 strategies, got sizes: $sizes")
    }

    @Test
    fun `boundary values appear in output`() {
        val seed = ByteArray(20) { 0x41 } // all 'A'
        val mutator = ByteMutator(Random(42))
        val allBytes = mutableSetOf<Byte>()
        repeat(2000) { mutator.mutate(seed).forEach { allBytes.add(it) } }
        // Boundary strategy injects 0x00, 0xFF, 0x7F, 0x80, 0x0A, 0x0D
        val boundaries = listOf<Byte>(0x00, 0xFF.toByte(), 0x7F, 0x80.toByte())
        val found = boundaries.count { it in allBytes }
        assertTrue(found >= 2, "expected boundary values in output, found $found of 4")
    }

    @Test
    fun `swap produces different byte order`() {
        val seed = byteArrayOf(1, 2, 3, 4, 5)
        val mutator = ByteMutator(Random(100))
        var swapped = false
        repeat(200) {
            val out = mutator.mutate(seed)
            // A swap of adjacent bytes changes order but keeps the same bytes
            if (out.size == seed.size && !out.contentEquals(seed) && out.toSet() == seed.toSet()) {
                swapped = true
            }
        }
        assertTrue(swapped, "expected at least one swap-adjacent mutation in 200 tries")
    }
}
