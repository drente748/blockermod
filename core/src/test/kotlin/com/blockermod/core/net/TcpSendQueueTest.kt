package com.blockermod.core.net

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TcpSendQueueTest {

    @Test
    fun `queue emits mss sized segments with sequential sequence numbers`() {
        val queue = TcpSendQueue(isn = 100L, mss = 4)
        assertTrue(queue.queue(ByteArray(10)))

        val emitted = ArrayList<Pair<Long, Int>>()
        queue.flush(100) { seq, data -> emitted += seq to data.size }

        assertEquals(listOf(101L to 4, 105L to 4, 109L to 2), emitted)
        assertEquals(111L, queue.sndNxt)
        assertEquals(10, queue.pendingByteCount())
    }

    @Test
    fun `flush honors the peer receive window`() {
        val queue = TcpSendQueue(isn = 100L, mss = 4)
        queue.queue(ByteArray(10))

        val first = ArrayList<Pair<Long, Int>>()
        queue.flush(3) { seq, data -> first += seq to data.size }
        assertEquals(listOf(101L to 3), first)

        val rest = ArrayList<Pair<Long, Int>>()
        queue.flush(100) { seq, data -> rest += seq to data.size }
        assertEquals(listOf(104L to 4, 108L to 3), rest)
    }

    @Test
    fun `zero window emits nothing but retains data`() {
        val queue = TcpSendQueue(isn = 100L, mss = 4)
        queue.queue(ByteArray(8))

        var emitted = 0
        queue.flush(0) { _, _ -> emitted++ }
        assertEquals(0, emitted)
        assertEquals(8, queue.pendingByteCount())

        queue.flush(100) { _, _ -> emitted++ }
        assertEquals(2, emitted)
    }

    @Test
    fun `onAck advances sndUna and drops fully acked segments`() {
        val queue = TcpSendQueue(isn = 100L, mss = 4)
        queue.queue(ByteArray(10))
        queue.flush(100) { _, _ -> }

        val freed = queue.onAck(105L)

        assertEquals(4, freed)
        assertEquals(105L, queue.sndUna)
        assertEquals(6, queue.pendingByteCount())
        assertEquals(0L, queue.unacked().first().seq - 105L)
    }

    @Test
    fun `onAck of a partial segment trims the acked prefix`() {
        val queue = TcpSendQueue(isn = 100L, mss = 4)
        queue.queue(ByteArray(8))
        queue.flush(100) { _, _ -> }

        val freed = queue.onAck(103L)

        assertEquals(2, freed)
        assertEquals(103L, queue.sndUna)
        assertEquals(6, queue.pendingByteCount())
        assertEquals(103L, queue.unacked().first().seq)
    }

    @Test
    fun `stale ack is a no op and beyond nxt clamps to all acked`() {
        val queue = TcpSendQueue(isn = 100L, mss = 4)
        queue.queue(ByteArray(8))
        queue.flush(100) { _, _ -> }

        queue.onAck(105L) // advance once
        assertEquals(0, queue.onAck(101L), "stale ACK must not free anything")
        assertEquals(105L, queue.sndUna)

        queue.onAck(1109L) // far ahead of SND.NXT (109) => clamped
        assertTrue(queue.allAcked())
        assertEquals(queue.sndNxt, queue.sndUna)
    }

    @Test
    fun `retransmit emits only unacked bytes and does not move sndNxt`() {
        val queue = TcpSendQueue(isn = 100L, mss = 4)
        queue.queue(ByteArray(10))
        queue.flush(100) { _, _ -> }
        queue.onAck(105L)
        val nxtBefore = queue.sndNxt

        val retransmitted = ArrayList<Pair<Long, ByteArray>>()
        queue.retransmit { seq, data -> retransmitted += seq to data }

        assertEquals(listOf(105L, 109L), retransmitted.map { it.first })
        assertEquals(nxtBefore, queue.sndNxt)
        assertEquals(6, retransmitted.sumOf { it.second.size })
    }

    @Test
    fun `sequence wraparound is handled`() {
        val queue = TcpSendQueue(isn = 0xFFFFFFFEL, mss = 4)
        queue.queue(ByteArray(10))
        val seqs = ArrayList<Long>()
        queue.flush(100) { seq, _ -> seqs += seq }

        assertEquals(listOf(0xFFFFFFFFL, 0x00000003L, 0x00000007L), seqs)
        queue.onAck(0x00000003L)
        assertEquals(0x00000003L, queue.sndUna)
    }

    @Test
    fun `pending bytes are bounded`() {
        val queue = TcpSendQueue(isn = 1L, mss = 64, maxPendingBytes = 128)
        assertTrue(queue.queue(ByteArray(128)))
        assertFalse(queue.queue(ByteArray(1)), "must fail closed at the memory bound")
        assertEquals(128, queue.pendingByteCount())
    }

    @Test
    fun `allAcked is false until every byte is acknowledged`() {
        val queue = TcpSendQueue(isn = 1L, mss = 4)
        assertTrue(queue.allAcked(), "an empty queue has nothing outstanding")
        queue.queue(ByteArray(8))
        queue.flush(100) { _, _ -> }
        assertFalse(queue.allAcked())
        queue.onAck(10L) // ISN=1 => data 2..9, so ACK 10 covers everything
        assertTrue(queue.allAcked())
    }
}
