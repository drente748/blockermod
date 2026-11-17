package com.blockermod.core.net

/**
 * Bounded outbound TCP send queue for the local DNS responder.
 *
 * Holds the contiguous byte range [SND.UNA, SND.NXT) in [buffer], tracks how much of it has been
 * emitted ([sentCount]), and slices it into MSS-sized segments on demand. An ACK advances SND.UNA
 * and frees the acknowledged prefix; unacknowledged bytes are retained for retransmission.
 *
 * No timer or thread is used: retransmission is driven by incoming ACKs/data/duplicate segments.
 * A local TUN has no real packet loss, so an RTO timer would only waste battery.
 *
 * Memory is bounded by [maxPendingBytes]: [queue] fails closed when exceeded, so a peer that never
 * acknowledges cannot grow the queue without limit.
 */
class TcpSendQueue(
    isn: Long,
    private val mss: Int,
    private val maxPendingBytes: Int = DEFAULT_MAX_PENDING_BYTES,
) {

    data class Segment(val seq: Long, val data: ByteArray)

    private var buffer: ByteArray = EMPTY
    private var sentCount: Int = 0
    private var sndUnaValue: Long = (isn + 1L) and SEQ_MASK
    private var sndNxtValue: Long = (isn + 1L) and SEQ_MASK

    /** Left edge of the send window (oldest unacknowledged byte). */
    val sndUna: Long get() = sndUnaValue

    /** Next sequence number to assign to new data. */
    val sndNxt: Long get() = sndNxtValue

    /** Bytes currently queued (sent-but-unacknowledged plus not-yet-sent). */
    fun pendingByteCount(): Int = buffer.size

    /**
     * Appends [payload] to the queue. Returns false when the memory bound would be exceeded; the
     * caller must fail closed instead of queueing unbounded data.
     */
    fun queue(payload: ByteArray): Boolean {
        if (payload.isEmpty()) return true
        if (buffer.size.toLong() + payload.size.toLong() > maxPendingBytes.toLong()) return false
        buffer = buffer + payload
        sndNxtValue = (sndNxtValue + payload.size.toLong()) and SEQ_MASK
        return true
    }

    /**
     * Emits unsent bytes that fit in [window], in MSS-sized slices, and marks them sent.
     * A zero window emits nothing (data is retained for a later window update).
     */
    fun flush(window: Int, emit: (Long, ByteArray) -> Unit) {
        if (window <= 0) return
        // The peer's window is relative to SND.UNA, i.e. to the start of our buffer. The right edge
        // is therefore SND.UNA + window = buffer offset [window], not [sentCount + window].
        val limit = minOf(buffer.size, window)
        var offset = sentCount
        while (offset < limit) {
            val length = minOf(mss, limit - offset)
            emit((sndUna + offset.toLong()) and SEQ_MASK, buffer.copyOfRange(offset, offset + length))
            offset += length
        }
        sentCount = offset
    }

    /**
     * Processes an ACK: advances SND.UNA, frees the acknowledged prefix, and returns the number of
     * bytes released. ACKs before SND.UNA are ignored; ACKs beyond SND.NXT are clamped.
     */
    fun onAck(acknowledgmentNumber: Long): Int {
        var ack = acknowledgmentNumber and SEQ_MASK
        if (distance(ack, sndNxt) < 0L) ack = sndNxt // bogus far-ahead ACK
        val advance = distance(sndUna, ack).coerceAtLeast(0L).coerceAtMost(buffer.size.toLong()).toInt()
        if (advance == 0) return 0
        buffer = buffer.copyOfRange(advance, buffer.size)
        sndUnaValue = (sndUna + advance.toLong()) and SEQ_MASK
        sentCount = maxOf(0, sentCount - advance)
        return advance
    }

    /** True when [acknowledgmentNumber] acknowledges no new data while some data is unacked. */
    fun isDuplicateAck(acknowledgmentNumber: Long): Boolean =
        distance(sndUna, acknowledgmentNumber and SEQ_MASK) <= 0L && hasUnacked()

    fun hasUnacked(): Boolean = sentCount > 0

    /** Snapshot of all emitted-but-unacknowledged segments for retransmission. */
    fun unacked(): List<Segment> {
        val out = ArrayList<Segment>()
        var offset = 0
        while (offset < sentCount) {
            val length = minOf(mss, sentCount - offset)
            out += Segment((sndUna + offset.toLong()) and SEQ_MASK, buffer.copyOfRange(offset, offset + length))
            offset += length
        }
        return out
    }

    /** Re-emits every emitted-but-unacknowledged segment, regardless of the current window. */
    fun retransmit(emit: (Long, ByteArray) -> Unit) = unacked().forEach { emit(it.seq, it.data) }

    /** True once all queued data has been acknowledged (safe to send FIN). */
    fun allAcked(): Boolean = buffer.isEmpty()

    /** Drops all queued data; called on RST/FIN/close. */
    fun clear() {
        buffer = EMPTY
        sentCount = 0
    }

    /** Signed distance ([to] - [from]) in the 32-bit TCP sequence space. */
    private fun distance(from: Long, to: Long): Long {
        val value = (to - from) and SEQ_MASK
        return if (value > 0x7FFFFFFFL) value - 0x1_0000_0000L else value
    }

    companion object {
        const val DEFAULT_MAX_PENDING_BYTES: Int = 128 * 1024
        const val MAX_MSS: Int = 1460
        private const val SEQ_MASK: Long = 0xFFFFFFFFL
        private val EMPTY = ByteArray(0)
    }
}
