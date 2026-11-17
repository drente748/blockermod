package com.blockermod.core.dns

/**
 * Two-octet length framing for DNS over TCP (RFC 7766 §9).
 *
 * DNS over TCP is a stream of `[length:2][message]`. Segment boundaries are not message boundaries:
 * one message may span many segments and one segment may hold several messages. This framer buffers
 * partial input and emits only complete messages, with hard limits on message size and buffered data.
 */
class DnsTcpFramer(
    private val maxMessageSize: Int = DEFAULT_MAX_MESSAGE,
    private val maxBufferedBytes: Int = DEFAULT_MAX_BUFFERED,
) {

    private var buffer: ByteArray = EMPTY

    /**
     * Feeds stream bytes and returns every complete DNS message found, in order.
     * Malformed lengths clear the buffer and mark [error]; the caller must close the connection.
     */
    fun feed(bytes: ByteArray): List<ByteArray> {
        if (bytes.isEmpty()) return EMPTY_LIST
        // A maximal legal message needs maxMessageSize + 2 buffered bytes, so the cap must never be
        // smaller than that or a full-size response would be rejected as malformed (B3).
        if (buffer.size + bytes.size > maxOf(maxBufferedBytes, maxMessageSize + 2)) {
            error = true
            buffer = EMPTY
            return EMPTY_LIST
        }
        buffer += bytes

        val messages = ArrayList<ByteArray>()
        while (buffer.size >= 2) {
            val length = ((buffer[0].toInt() and 0xFF) shl 8) or (buffer[1].toInt() and 0xFF)
            if (length < MIN_DNS_MESSAGE || length > maxMessageSize) {
                error = true
                buffer = EMPTY
                return EMPTY_LIST
            }
            if (buffer.size < length + 2) break
            messages += buffer.copyOfRange(2, 2 + length)
            buffer = buffer.copyOfRange(length + 2, buffer.size)
        }
        return if (messages.isEmpty()) EMPTY_LIST else messages
    }

    /** True when a malformed length or an exceeded limit was seen; the stream is unusable. */
    var error: Boolean = false
        private set

    /** Bytes of an incomplete message currently buffered. */
    fun pendingSize(): Int = buffer.size

    /** Discards partial state when the TCP connection closes before a message completed. */
    fun reset() {
        buffer = EMPTY
        error = false
    }

    companion object {
        /** DNS over TCP messages must fit in 16 bits; 4 KiB covers ordinary resolver answers. */
        const val DEFAULT_MAX_MESSAGE: Int = 4096

        /** The RFC 7766 maximum: a DNS-over-TCP message is bounded by the 16-bit length prefix. */
        const val MAX_MESSAGE: Int = 0xFFFF
        const val DEFAULT_MAX_BUFFERED: Int = 64 * 1024
        private const val MIN_DNS_MESSAGE: Int = 12
        val EMPTY = ByteArray(0)
        val EMPTY_LIST = emptyList<ByteArray>()
    }
}

/** Frames a DNS message for TCP transport: `[length:2][message]` in one buffer. */
fun frameDnsTcp(message: ByteArray): ByteArray {
    require(message.size in 12..0xFFFF) { "invalid DNS message size: ${message.size}" }
    return byteArrayOf(
        (message.size ushr 8).toByte(),
        message.size.toByte(),
    ) + message
}

/** True when the DNS header has the TC (truncated) bit set; the client must retry over TCP. */
// TC is bit 9 of the 16-bit flags word at offset 2, i.e. bit 1 of the high byte (offset 2).
// Byte 3's 0x02 is RCODE bit 1 (SERVFAIL) and must NOT be treated as truncation.
fun isDnsTruncated(message: ByteArray): Boolean =
    message.size >= 4 && (message[2].toInt() and 0x02) != 0
