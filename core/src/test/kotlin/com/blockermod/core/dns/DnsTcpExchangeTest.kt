package com.blockermod.core.dns

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals

class DnsTcpExchangeTest {

    @Test
    fun `reads a response split across several tcp reads`() {
        val query = ByteArray(12) { it.toByte() }.also { it[1] = 0x2A }
        val response = ByteArray(20).also {
            it[0] = query[0]
            it[1] = query[1]
            it[2] = 0x80.toByte() // QR bit: this is an answer, not an echoed query
        }
        val stream = ByteArrayInputStream(frameDnsTcp(response))
        val transport = object : DnsTcpTransport {
            override val input = object : java.io.InputStream() {
                var position = 0
                override fun read(): Int = stream.read()
                override fun read(bytes: ByteArray, off: Int, len: Int): Int {
                    // Deliver three bytes at a time to exercise the framer.
                    return stream.read(bytes, off, minOf(len, 3))
                }
            }
            override val output = ByteArrayOutputStream()
            override fun close() = Unit
        }

        val result = DnsTcpExchange().exchange(transport, query) as DnsTcpExchange.Outcome.Message

        assertEquals(response.toList(), result.bytes.toList())
        assertEquals(frameDnsTcp(query).toList(), (transport.output as ByteArrayOutputStream).toByteArray().toList())
    }

    @Test
    fun `ignores unrelated message ids on a reused connection`() {
        val query = ByteArray(12).also { it[1] = 5 }
        val wrong = ByteArray(12).also { it[1] = 6; it[2] = 0x80.toByte() }
        val right = ByteArray(12).also { it[1] = 5; it[2] = 0x80.toByte() }
        val stream = ByteArrayInputStream(frameDnsTcp(wrong) + frameDnsTcp(right))
        val transport = object : DnsTcpTransport {
            override val input = stream
            override val output = ByteArrayOutputStream()
            override fun close() = Unit
        }

        val result = DnsTcpExchange().exchange(transport, query) as DnsTcpExchange.Outcome.Message

        assertEquals(right.toList(), result.bytes.toList())
    }

    @Test
    fun `returns closed when the peer disconnects mid message`() {
        val query = ByteArray(12)
        val transport = object : DnsTcpTransport {
            override val input = ByteArrayInputStream(byteArrayOf(0, 20, 1, 2))
            override val output = ByteArrayOutputStream()
            override fun close() = Unit
        }

        assertEquals(DnsTcpExchange.Outcome.Closed, DnsTcpExchange().exchange(transport, query))
    }

    @Test
    fun `returns invalid when a length is malformed`() {
        val query = ByteArray(12)
        val transport = object : DnsTcpTransport {
            override val input = ByteArrayInputStream(byteArrayOf(0, 2, 1, 2))
            override val output = ByteArrayOutputStream()
            override fun close() = Unit
        }

        assertEquals(DnsTcpExchange.Outcome.Invalid, DnsTcpExchange().exchange(transport, query))
    }

    @Test
    fun `rejects an echoed query with matching id but no QR bit`() {
        // A broken/malicious server echoing the query (same ID, QR=0) must not be accepted as an
        // answer — otherwise a NODATA result is cached and the real answer is never fetched.
        val query = ByteArray(12).also { it[1] = 9 }
        val echo = ByteArray(12).also { it[1] = 9 } // QR = 0
        val transport = object : DnsTcpTransport {
            override val input = ByteArrayInputStream(frameDnsTcp(echo))
            override val output = ByteArrayOutputStream()
            override fun close() = Unit
        }

        // The echo never matches; the peer then closes, so the exchange ends Closed (fail closed).
        assertEquals(DnsTcpExchange.Outcome.Closed, DnsTcpExchange().exchange(transport, query))
    }
}
