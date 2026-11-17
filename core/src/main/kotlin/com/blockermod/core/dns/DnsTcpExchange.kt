package com.blockermod.core.dns

import java.io.InputStream
import java.io.OutputStream

/**
 * Abstract, testable transport for DNS-over-TCP (RFC 7766). The Android implementation supplies a
 * protected socket; unit tests supply in-memory streams.
 */
interface DnsTcpTransport : AutoCloseable {
    val input: InputStream
    val output: OutputStream

    /** Applies the remaining read deadline to a blocking socket; no-op for in-memory transports. */
    fun setReadTimeout(millis: Int) = Unit
}

/**
 * Performs one DNS-over-TCP query/response exchange with correct two-octet framing and limits.
 *
 * A single ABSOLUTE deadline governs the whole exchange (set once, never renewed per read), so a
 * peer that dribbles bytes cannot keep the call alive forever. The per-read timeout is only the
 * blocking bound handed to the transport; the deadline check is authoritative.
 *
 * A response is accepted only when the DNS ID matches, the QR bit is set, and the question section
 * matches the query (case-insensitively). This prevents accepting an echoed query or a reply to a
 * different question on a reused connection.
 */
class DnsTcpExchange(
    private val maxMessageSize: Int = DnsTcpFramer.DEFAULT_MAX_MESSAGE,
    private val readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT_MILLIS,
    private val nowNanos: () -> Long = { System.nanoTime() },
) {

    /** Result of an exchange: the DNS message, or a reason to retry/fail. */
    sealed interface Outcome {
        data class Message(val bytes: ByteArray) : Outcome
        data object Closed : Outcome
        data object Invalid : Outcome
    }

    fun exchange(transport: DnsTcpTransport, query: ByteArray, expectedQuestion: ByteArray? = null): Outcome {
        // A DNS message is at least a 12-byte header; shorter input fails closed before framing.
        if (query.size < 12) return Outcome.Invalid
        val framed = frameDnsTcp(query)
        val expectedId = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
        val question = expectedQuestion ?: extractQuestion(query)
        val deadline = nowNanos() + readTimeoutMillis.toLong() * 1_000_000L

        return try {
            transport.output.write(framed)
            transport.output.flush()

            val framer = DnsTcpFramer(maxMessageSize = maxMessageSize)
            val buffer = ByteArray(BUFFER_SIZE)
            var reads = 0
            while (reads < MAX_READS) {
                val remainingNanos = deadline - nowNanos()
                if (remainingNanos <= 0L) return Outcome.Closed
                // Bound each blocking read by the remaining absolute deadline (rounded up to 1 ms).
                transport.setReadTimeout(maxOf(1L, remainingNanos / 1_000_000L + 1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())

                val count = transport.input.read(buffer)
                if (count <= 0) return Outcome.Closed
                reads++

                val messages = framer.feed(buffer.copyOf(count))
                if (framer.error) return Outcome.Invalid
                for (message in messages) {
                    if (message.size < 12) return Outcome.Invalid
                    val id = ((message[0].toInt() and 0xFF) shl 8) or (message[1].toInt() and 0xFF)
                    val isResponse = message[2].toInt() and 0x80 != 0
                    if (id == expectedId && isResponse && sameQuestion(question, extractQuestion(message))) {
                        return Outcome.Message(message)
                    }
                }
            }
            Outcome.Invalid
        } catch (exception: Exception) {
            // Any transport failure fails closed instead of escaping into a worker thread or being
            // mistaken for a valid answer.
            Outcome.Closed
        }
    }

    private companion object {
        const val DEFAULT_READ_TIMEOUT_MILLIS: Int = 2_000
        const val BUFFER_SIZE: Int = 4096
        const val MAX_READS: Int = 256
    }
}
