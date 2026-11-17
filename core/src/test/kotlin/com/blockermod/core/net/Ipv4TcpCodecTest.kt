package com.blockermod.core.net

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Ipv4TcpCodecTest {

    @Test
    fun `parses a syn packet`() {
        val packet = buildTcp(flags = Ipv4TcpCodec.Flags.SYN)

        val parsed = Ipv4TcpCodec.parse(packet)

        assertNotNull(parsed)
        assertEquals(40_000, parsed.sourcePort)
        assertEquals(443, parsed.destinationPort)
        assertEquals(100L, parsed.sequenceNumber)
        assertEquals(Ipv4TcpCodec.Flags.SYN, parsed.flags and Ipv4TcpCodec.Flags.SYN)
        assertEquals(0, parsed.payload.size)
    }

    @Test
    fun `parses payload and options`() {
        val packet = buildTcp(
            flags = Ipv4TcpCodec.Flags.PSH or Ipv4TcpCodec.Flags.ACK,
            payload = byteArrayOf(1, 2, 3, 4),
            options = Ipv4TcpCodec.mssOption(1460),
        )

        val parsed = Ipv4TcpCodec.parse(packet)

        assertNotNull(parsed)
        assertEquals(4, parsed.payload.size)
        assertEquals(4, byteArrayOf(*parsed.payload).contentEquals(byteArrayOf(1, 2, 3, 4)).let { if (it) 4 else 0 })
        assertEquals(24, parsed.tcpHeaderLength)
    }

    @Test
    fun `builds a response with swapped endpoints`() {
        val request = Ipv4TcpCodec.parse(buildTcp(flags = Ipv4TcpCodec.Flags.SYN)) ?: error("parse failed")

        val response = Ipv4TcpCodec.build(
            request = request,
            payload = EMPTY,
            sequenceNumber = 500L,
            acknowledgmentNumber = 101L,
            flags = Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK,
            options = Ipv4TcpCodec.mssOption(1460),
        )
        val parsed = Ipv4TcpCodec.parse(response)

        assertNotNull(parsed)
        assertEquals(443, parsed.sourcePort)
        assertEquals(40_000, parsed.destinationPort)
        assertEquals(500L, parsed.sequenceNumber)
        assertEquals(101L, parsed.acknowledgmentNumber)
        assertEquals(0x12, parsed.flags)
    }

    @Test
    fun `rejects a non-tcp packet`() {
        val packet = buildTcp(flags = Ipv4TcpCodec.Flags.SYN)
        packet[9] = 17 // UDP

        assertNull(Ipv4TcpCodec.parse(packet))
    }

    @Test
    fun `rejects a truncated packet`() {
        val packet = buildTcp(flags = Ipv4TcpCodec.Flags.SYN)

        assertNull(Ipv4TcpCodec.parse(packet.copyOf(30)))
    }

    @Test
    fun `rejects a first fragment with the more fragments bit set`() {
        val packet = buildTcp(flags = Ipv4TcpCodec.Flags.SYN, moreFragments = true)

        assertNull(Ipv4TcpCodec.parse(packet))
    }

    @Test
    fun `reset follows the RFC 5961 sequence numbers`() {
        // A reset answering an ACK takes SEQ from the incoming ACK and ACK from SEG.SEQ+SEG.LEN.
        val withAck = Ipv4TcpCodec.parse(buildTcp(
            flags = Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK,
            ack = 500L,
            payload = byteArrayOf(1, 2, 3),
        ))!!
        val reset = Ipv4TcpCodec.parse(Ipv4TcpCodec.reset(withAck))!!

        assertEquals(500L, reset.sequenceNumber)
        assertEquals(104L, reset.acknowledgmentNumber) // 100 + SYN + 3 bytes
        assertEquals(Ipv4TcpCodec.Flags.RST or Ipv4TcpCodec.Flags.ACK, reset.flags)

        // A pure SYN has no ACK field: SEQ = ACK = SEG.SEQ + 1.
        val syn = Ipv4TcpCodec.parse(buildTcp(flags = Ipv4TcpCodec.Flags.SYN))!!
        val resetSyn = Ipv4TcpCodec.parse(Ipv4TcpCodec.reset(syn))!!
        assertEquals(101L, resetSyn.sequenceNumber)
        assertEquals(101L, resetSyn.acknowledgmentNumber)
    }

    private fun buildTcp(
        flags: Int,
        payload: ByteArray = EMPTY,
        options: ByteArray = EMPTY,
        ack: Long = 0L,
        moreFragments: Boolean = false,
    ): ByteArray {
        val tcpHeader = 20 + options.size
        val tcpLength = tcpHeader + payload.size
        val total = 20 + tcpLength
        val p = ByteArray(total)

        p[0] = 0x45
        writeU16(p, 2, total)
        writeU16(p, 4, 0x1234)
        writeU16(p, 6, if (moreFragments) 0x6000 else 0x4000) // DF, or DF|MF
        p[8] = 64
        p[9] = 6
        writeU32(p, 12, 0x0A000001)
        writeU32(p, 16, 0x0A000003)
        writeU16(p, 10, checksum(p, 0, 20))

        val t = 20
        writeU16(p, t, 40_000)
        writeU16(p, t + 2, 443)
        writeU32(p, t + 4, 100L)
        writeU32(p, t + 8, ack)
        p[t + 12] = ((tcpHeader / 4) shl 4).toByte()
        p[t + 13] = (flags and 0x3F).toByte()
        writeU16(p, t + 14, 64_000)
        options.copyInto(p, t + 20)
        payload.copyInto(p, t + tcpHeader)

        return p
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i + 1 < offset + length) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum and 0xFFFF).inv() and 0xFFFF
    }

    private fun writeU16(p: ByteArray, o: Int, v: Int) {
        p[o] = ((v ushr 8) and 0xFF).toByte()
        p[o + 1] = (v and 0xFF).toByte()
    }

    private fun writeU32(p: ByteArray, o: Int, v: Long) {
        p[o] = ((v ushr 24) and 0xFF).toByte()
        p[o + 1] = ((v ushr 16) and 0xFF).toByte()
        p[o + 2] = ((v ushr 8) and 0xFF).toByte()
        p[o + 3] = (v and 0xFF).toByte()
    }

    private companion object {
        val EMPTY = ByteArray(0)
    }
}
