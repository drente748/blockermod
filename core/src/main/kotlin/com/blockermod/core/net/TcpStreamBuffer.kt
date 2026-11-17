package com.blockermod.core.net

/**
 * Reassembles an inbound TCP byte stream from IPv4 segments.
 *
 * TCP is a stream: segment boundaries are not message boundaries. This class keeps the next expected
 * sequence number, accepts in-order bytes, and rejects duplicates, pure ACKs and out-of-order gaps
 * (returning null without changing the buffer). The caller must ACK with [acknowledgmentNumber]
 * after a rejected segment so the peer can retransmit a lost one; buffered bytes are only removed by
 * [drain].
 *
 * The buffer is bounded: a peer that never completes a message cannot grow it past [maxBufferedBytes].
 */
class TcpStreamBuffer(
    private val maxBufferedBytes: Int = DEFAULT_MAX_BUFFERED,
) {

    /** True once the first SYN has been accepted and a sequence window exists. */
    var started: Boolean = false
        private set

    /** Next sequence number expected from the peer (RCV.NXT). */
    var expectedSequence: Long = 0L
        private set

    /** True when the peer's FIN has been received and acknowledged. */
    var inputClosed: Boolean = false
        private set

    private var buffer: ByteArray = EMPTY

    /** Accepts SYN and marks the start of the stream. Returns whether it was accepted. */
    fun start(sequenceNumber: Long): Boolean {
        if (started) return false
        started = true
        expectedSequence = (sequenceNumber + 1L) and 0xFFFFFFFFL
        return true
    }

    /**
     * Accepts one inbound segment.
     *
     * @return the reassembled, in-order bytes, or null when the segment was a duplicate, too old, or
     *   created a gap that requires a retransmission.
     */
    fun accept(sequenceNumber: Long, payload: ByteArray, fin: Boolean = false): ByteArray? {
        if (!started || inputClosed) return null
        val seq = sequenceNumber and 0xFFFFFFFFL

        val offset = relativeDistance(seq, expectedSequence)
        if (payload.isEmpty()) {
            // Pure ACK from the peer: no bytes to reassemble. A FIN still consumes one sequence.
            if (fin && offset == 0L) {
                inputClosed = true
                expectedSequence = (expectedSequence + 1L) and 0xFFFFFFFFL
            }
            return null
        }

        if (offset != 0L) return null // duplicate or gap: caller sends an ACK with expectedSequence

        if (buffer.size + payload.size > maxBufferedBytes) return null
        buffer = buffer + payload
        expectedSequence = (expectedSequence + payload.size.toLong()) and 0xFFFFFFFFL

        if (fin) {
            inputClosed = true
            expectedSequence = (expectedSequence + 1L) and 0xFFFFFFFFL
        }
        return payload.copyOf()
    }

    /** Returns all buffered bytes and clears the buffer. */
    fun drain(): ByteArray {
        val result = buffer
        buffer = EMPTY
        return result
    }

    /** Current buffer size in bytes. */
    fun bufferedSize(): Int = buffer.size

    /** All accumulated bytes without consuming them; used for stream-based TLS inspection. */
    fun buffered(): ByteArray = buffer.copyOf()

    fun reset() {
        started = false
        inputClosed = false
        expectedSequence = 0L
        buffer = EMPTY
    }

    /** Signed distance from [from] to [to] in the 32-bit TCP sequence space. */
    private fun relativeDistance(from: Long, to: Long): Long {
        val value = (from - to) and 0xFFFFFFFFL
        return if (value > 0x7FFFFFFFL) value - 0x100000000L else value
    }

    private companion object {
        const val DEFAULT_MAX_BUFFERED: Int = 64 * 1024
        val EMPTY = ByteArray(0)
    }
}
