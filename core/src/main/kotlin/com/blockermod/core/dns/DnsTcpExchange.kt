package com.blockermod.core.dns

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Abstract, testable transport for DNS-over-TCP (RFC 7766). The Android implementation supplies a
 * protected socket; unit tests supply in-memory streams.
 */
interface DnsTcpTransport : AutoCloseable {
    val input: InputStream
    val output: OutputStream
}

/**
 * Performs one DNS-over-TCP query/response exchange with correct two-octet framing and limits.
 *
 * A response may be preceded by a short TCP read (or arrive split across segments), so reads go
 * through [DnsTcpFramer]. Only the message with the matching DNS ID is returned; other messages on a
 * reused connection are ignored. Timeouts are enforced by the transport implementation.
 */
class DnsTcpExchange(
    private val maxMessageSize: Int = DnsTcpFramer.DEFAULT_MAX_MESSAGE,
) {

    /** Result of an exchange: the DNS message, or a reason to retry/fail. */
    sealed interface Outcome {
        data class Message(val bytes: ByteArray) : Outcome
        data object Closed : Outcome
        data object Invalid : Outcome
    }

    fun exchange(transport: DnsTcpTransport, query: ByteArray): Outcome {
        val framed = frameDnsTcp(query)
        return try {
            transport.output.write(framed)
            transport.output.flush()

            val framer = DnsTcpFramer(maxMessageSize = maxMessageSize)
            val buffer = ByteArray(BUFFER_SIZE)
            val expectedId = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
            var read = 0
            while (read < MAX_READS) {
                val count = transport.input.read(buffer)
                if (count <= 0) return Outcome.Closed
                read++
                val messages = framer.feed(buffer.copyOf(count))
                if (framer.error) return Outcome.Invalid
                for (message in messages) {
                    if (message.size < 12) return Outcome.Invalid
                    val id = ((message[0].toInt() and 0xFF) shl 8) or (message[1].toInt() and 0xFF)
                    // QR bit must be set: a server echoing our query is not an answer. Matches the
                    // validation the UDP path already performs.
                    val isResponse = message[2].toInt() and 0x80 != 0
                    if (id == expectedId && isResponse) return Outcome.Message(message)
                }
            }
            Outcome.Invalid
        } catch (exception: Exception) {
            // Any transport failure (I/O or otherwise) fails closed instead of escaping into a
            // worker thread or being mistaken for a valid answer.
            Outcome.Closed
        }
    }

    private companion object {
        const val BUFFER_SIZE: Int = 4096
        const val MAX_READS: Int = 64
    }
}
