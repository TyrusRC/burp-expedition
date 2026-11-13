package expedition.framing

import java.nio.ByteOrder

/**
 * Splits one direction of a TCP byte stream into application messages.
 *
 * A framer is stateful (it accumulates bytes between reads) and belongs to exactly one
 * (connection, direction). It never strips or rewrites anything: the concatenation of every
 * message it emits plus [flush] is byte-for-byte the input stream, so forwarding the emitted
 * messages reproduces the stream exactly.
 *
 * Not thread-safe; callers serialise access (TcpConnection locks per framer).
 */
interface Framer {
    /** Feed the next chunk read from the socket; returns the complete messages it finished (possibly none). */
    fun feed(chunk: ByteArray): List<ByteArray>

    /** Return (and clear) any buffered, not-yet-complete bytes — called when the connection closes. */
    fun flush(): ByteArray?
}

/** Default bound on bytes buffered while waiting for a frame to complete (anti-OOM). */
const val DEFAULT_MAX_FRAME_BYTES = 1 shl 20 // 1 MiB

/**
 * Immutable framing choice carried by a listener config. Each connection asks it for two fresh
 * framers (one per direction) — the spec itself holds no stream state.
 */
sealed class FramingSpec {
    abstract fun newFramer(onWarning: (String) -> Unit = {}): Framer

    /** Every socket read is one message — the historical behaviour (default). */
    object Passthrough : FramingSpec() {
        override fun newFramer(onWarning: (String) -> Unit): Framer = PassthroughFramer
        override fun toString() = "Passthrough"
    }

    /**
     * Length-prefixed frames. Total frame size =
     * `lengthFieldOffset + lengthFieldSize + <length value> + lengthAdjustment`; the emitted
     * message is the whole frame including its header.
     */
    data class LengthPrefix(
        val lengthFieldOffset: Int = 0,
        val lengthFieldSize: Int = 4,
        val byteOrder: ByteOrder = ByteOrder.BIG_ENDIAN,
        val lengthAdjustment: Int = 0,
        val maxFrameBytes: Int = DEFAULT_MAX_FRAME_BYTES,
    ) : FramingSpec() {
        init {
            require(lengthFieldOffset >= 0) { "length field offset must be >= 0" }
            require(lengthFieldSize in setOf(1, 2, 3, 4, 8)) { "length field size must be 1, 2, 3, 4 or 8" }
            require(maxFrameBytes >= lengthFieldOffset + lengthFieldSize) { "max frame bytes smaller than the length header" }
        }
        override fun newFramer(onWarning: (String) -> Unit): Framer = LengthPrefixFramer(this, onWarning)
    }

    /** Delimiter-terminated messages (e.g. `\r\n`, `\n`); the delimiter stays in the message. */
    class Delimiter(delimiter: ByteArray, val maxFrameBytes: Int = DEFAULT_MAX_FRAME_BYTES) : FramingSpec() {
        private val delim = delimiter.copyOf()
        val delimiter: ByteArray get() = delim.copyOf()

        init {
            require(delim.isNotEmpty()) { "delimiter must not be empty" }
            require(maxFrameBytes >= delim.size) { "max frame bytes smaller than the delimiter" }
        }

        override fun newFramer(onWarning: (String) -> Unit): Framer = DelimiterFramer(delim, maxFrameBytes, onWarning)
        override fun equals(other: Any?) = other is Delimiter && other.delim.contentEquals(delim) && other.maxFrameBytes == maxFrameBytes
        override fun hashCode() = delim.contentHashCode() * 31 + maxFrameBytes
        override fun toString() = "Delimiter(${delim.joinToString("") { "%02x".format(it) }}, max=$maxFrameBytes)"
    }
}

/** Stateless: every chunk is a message, nothing is buffered. */
object PassthroughFramer : Framer {
    override fun feed(chunk: ByteArray): List<ByteArray> = if (chunk.isEmpty()) emptyList() else listOf(chunk)
    override fun flush(): ByteArray? = null
}

/** Growable byte buffer with cheap prefix removal. */
internal class ByteAccumulator {
    private var data = ByteArray(256)
    private var start = 0
    private var end = 0
    val size: Int get() = end - start

    fun append(src: ByteArray, off: Int = 0, len: Int = src.size - off) {
        if (len <= 0) return
        if (end + len > data.size) {
            val needed = size + len
            if (needed <= data.size && start > 0) {
                System.arraycopy(data, start, data, 0, size)
            } else {
                val grown = ByteArray(maxOf(needed, data.size * 2))
                System.arraycopy(data, start, grown, 0, size)
                data = grown
            }
            end = size; start = 0
        }
        System.arraycopy(src, off, data, end, len)
        end += len
    }

    operator fun get(i: Int): Byte = data[start + i]

    /** Remove and return the first [n] bytes. */
    fun take(n: Int): ByteArray {
        val out = data.copyOfRange(start, start + n)
        start += n
        if (start == end) { start = 0; end = 0; if (data.size > 64 * 1024) data = ByteArray(256) }
        return out
    }

    fun takeAll(): ByteArray = take(size)

    fun indexOf(needle: ByteArray, from: Int): Int {
        var i = from
        val last = size - needle.size
        outer@ while (i <= last) {
            for (j in needle.indices) if (data[start + i + j] != needle[j]) { i++; continue@outer }
            return i
        }
        return -1
    }
}

internal class LengthPrefixFramer(
    private val spec: FramingSpec.LengthPrefix,
    private val onWarning: (String) -> Unit,
) : Framer {
    private val buf = ByteAccumulator()
    private val headerSize = spec.lengthFieldOffset + spec.lengthFieldSize
    /** Bytes of an oversized frame still to be passed through raw (keeps us in sync). */
    private var skipRemaining = 0L

    override fun feed(chunk: ByteArray): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        var pos = 0
        if (skipRemaining > 0) {
            val n = minOf(skipRemaining, chunk.size.toLong()).toInt()
            if (n > 0) out += chunk.copyOfRange(0, n)
            skipRemaining -= n
            pos = n
        }
        buf.append(chunk, pos, chunk.size - pos)
        while (buf.size >= headerSize) {
            val frame = headerSize.toLong() + readLength() + spec.lengthAdjustment
            if (frame < headerSize || frame <= 0) {
                onWarning("length-prefix framer: invalid frame length $frame; flushing ${buf.size} buffered bytes raw (stream may be out of sync)")
                out += buf.takeAll()
                break
            }
            if (buf.size >= frame) {
                out += buf.take(frame.toInt())
                continue
            }
            if (frame > spec.maxFrameBytes) {
                // Never buffer more than the cap: emit what we have and pass the rest of this
                // frame through unbuffered, then resume framing at the next header.
                onWarning("length-prefix framer: frame of $frame bytes exceeds max ${spec.maxFrameBytes}; passing it through unframed")
                val emitted = buf.size
                out += buf.takeAll()
                skipRemaining = frame - emitted
            }
            break
        }
        return out
    }

    private fun readLength(): Long {
        var v = 0L
        val n = spec.lengthFieldSize
        for (k in 0 until n) {
            val idx = if (spec.byteOrder == java.nio.ByteOrder.BIG_ENDIAN) k else n - 1 - k
            v = (v shl 8) or (buf[spec.lengthFieldOffset + idx].toLong() and 0xFF)
        }
        // An 8-byte field can exceed Long.MAX_VALUE; treat as invalid (negative) rather than wrap.
        return v
    }

    override fun flush(): ByteArray? {
        skipRemaining = 0
        return if (buf.size == 0) null else buf.takeAll()
    }
}

internal class DelimiterFramer(
    private val delimiter: ByteArray,
    private val maxFrameBytes: Int,
    private val onWarning: (String) -> Unit,
) : Framer {
    private val buf = ByteAccumulator()
    /** Where the next delimiter search starts — avoids rescanning bytes already checked. */
    private var scanFrom = 0

    override fun feed(chunk: ByteArray): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        buf.append(chunk)
        while (true) {
            val idx = buf.indexOf(delimiter, scanFrom)
            if (idx < 0) { scanFrom = maxOf(0, buf.size - delimiter.size + 1); break }
            out += buf.take(idx + delimiter.size)
            scanFrom = 0
        }
        if (buf.size > maxFrameBytes) {
            onWarning("delimiter framer: ${buf.size} bytes without a delimiter exceeds max $maxFrameBytes; flushing raw")
            out += buf.takeAll()
            scanFrom = 0
        }
        return out
    }

    override fun flush(): ByteArray? {
        scanFrom = 0
        return if (buf.size == 0) null else buf.takeAll()
    }
}
