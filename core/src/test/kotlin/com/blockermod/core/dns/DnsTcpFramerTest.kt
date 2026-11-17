package com.blockermod.core.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsTcpFramerTest {

    @Test
    fun `frame adds a two byte length prefix`() {
        val framed = frameDnsTcp(ByteArray(12))

        assertEquals(14, framed.size)
        assertEquals(0, framed[0].toInt())
        assertEquals(12, framed[1].toInt())
    }

    @Test
    fun `parses a message split into single byte segments`() {
        val framer = DnsTcpFramer()
        val framed = frameDnsTcp(ByteArray(20))

        var emitted: List<ByteArray> = emptyList()
        for (byte in framed) emitted = emitted + framer.feed(byteArrayOf(byte))

        assertEquals(1, emitted.size)
        assertEquals(20, emitted[0].size)
        assertEquals(0, framer.pendingSize())
    }

    @Test
    fun `parses several messages in one segment`() {
        val framer = DnsTcpFramer()
        val first = frameDnsTcp(ByteArray(12) { it.toByte() })
        val second = frameDnsTcp(ByteArray(14) { it.toByte() })

        val emitted = framer.feed(first + second)

        assertEquals(2, emitted.size)
        assertEquals(12, emitted[0].size)
        assertEquals(14, emitted[1].size)
    }

    @Test
    fun `rejects an invalid length`() {
        val framer = DnsTcpFramer()

        val emitted = framer.feed(byteArrayOf(0, 3, 1, 2, 3))

        assertTrue(emitted.isEmpty())
        assertTrue(framer.error)
    }

    @Test
    fun `rejects a message larger than the limit`() {
        val framer = DnsTcpFramer(maxMessageSize = 64)

        val emitted = framer.feed(byteArrayOf(0, 65) + ByteArray(65))

        assertTrue(emitted.isEmpty())
        assertTrue(framer.error)
    }

    @Test
    fun `reset clears partial state`() {
        val framer = DnsTcpFramer()
        framer.feed(byteArrayOf(0, 20, 1))
        assertEquals(3, framer.pendingSize())

        framer.reset()

        assertEquals(0, framer.pendingSize())
        assertFalse(framer.error)
    }

    @Test
    fun `detects the TC bit on a truncated upstream answer`() {
        // TC is bit 9 of the flags word at offset 2 => 0x02 in the HIGH flags byte (index 2).
        val truncated = ByteArray(12).also { it[2] = 0x02 }

        assertTrue(isDnsTruncated(truncated))
        assertFalse(isDnsTruncated(ByteArray(12)))
    }

    @Test
    fun `does not mistake SERVFAIL rcode for truncation`() {
        // 0x02 in the LOW flags byte (index 3) is RCODE=2 (SERVFAIL), NOT the TC bit.
        val servfail = ByteArray(12).also { it[3] = 0x02 }

        assertFalse(isDnsTruncated(servfail))
    }
}
