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
    fun `does not grow the payload without bound`() {
        val seed = ByteArray(10)
        val mutator = ByteMutator(Random(3))
        repeat(100) { assertTrue(mutator.mutate(seed).size <= seed.size + 1) }
    }
}
