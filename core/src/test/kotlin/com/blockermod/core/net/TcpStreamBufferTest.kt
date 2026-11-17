package com.blockermod.core.net

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TcpStreamBufferTest {

    @Test
    fun `reassembles a message split across segments`() {
        val stream = TcpStreamBuffer()
        assertTrue(stream.start(100L))

        val first = stream.accept(101L, byteArrayOf(1, 2))
        val second = stream.accept(103L, byteArrayOf(3, 4))

        assertEquals(listOf(1.toByte(), 2.toByte()), first?.toList())
        assertEquals(listOf(3.toByte(), 4.toByte()), second?.toList())
        assertEquals(105L, stream.expectedSequence)
    }

    @Test
    fun `duplicate segment is ignored`() {
        val stream = TcpStreamBuffer()
        stream.start(10L)

        assertEquals(byteArrayOf(9, 9).toList(), stream.accept(11L, byteArrayOf(9, 9))?.toList())
        assertNull(stream.accept(11L, byteArrayOf(9, 9)))
    }

    @Test
    fun `gap is rejected without advancing the window`() {
        val stream = TcpStreamBuffer()
        stream.start(0L)

        assertNull(stream.accept(10L, byteArrayOf(1)))
        assertEquals(1L, stream.expectedSequence)
        assertEquals(byteArrayOf(2).toList(), stream.accept(1L, byteArrayOf(2))?.toList())
    }

    @Test
    fun `sequence wraparound is handled`() {
        val stream = TcpStreamBuffer()
        stream.start(0xFFFFFFFEU.toLong())

        assertEquals(0xFFFFFFFFL, stream.expectedSequence)
        stream.accept(0xFFFFFFFFL, byteArrayOf(7))
        assertEquals(0L, stream.expectedSequence)
    }

    @Test
    fun `fin consumes one sequence number and closes input`() {
        val stream = TcpStreamBuffer()
        stream.start(5L)

        stream.accept(6L, byteArrayOf(1), fin = true)

        assertTrue(stream.inputClosed)
        assertEquals(8L, stream.expectedSequence)
        assertNull(stream.accept(8L, byteArrayOf(2)))
    }

    @Test
    fun `duplicate syn does not restart the stream`() {
        val stream = TcpStreamBuffer()
        assertTrue(stream.start(100L))
        assertFalse(stream.start(500L))
        assertEquals(101L, stream.expectedSequence)
    }

    @Test
    fun `buffer is bounded`() {
        val stream = TcpStreamBuffer(maxBufferedBytes = 4)
        stream.start(0L)

        stream.accept(1L, ByteArray(4))
        val accepted = stream.accept(5L, ByteArray(1))

        assertNull(accepted)
        assertEquals(4, stream.bufferedSize())
    }
}
