package com.blockermod.core.net

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Ipv4UdpCodecTest {

    @Test
    fun `parses a valid packet`() {
        val payload = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val packet = buildPacket(payload = payload)

        val parsed = Ipv4UdpCodec.parseIpv4Udp(packet)

        assertNotNull(parsed)
        assertEquals(0x0A000001, parsed.sourceAddress)
        assertEquals(0x0A000002, parsed.destinationAddress)
        assertEquals(5353, parsed.sourcePort)
        assertEquals(53, parsed.destinationPort)
        assertEquals(4, parsed.payload.size)
        assertEquals(0x01, parsed.payload[0].toInt())
    }

    @Test
    fun `rejects a packet that is not ipv4`() {
        assertNull(Ipv4UdpCodec.parseIpv4Udp(buildPacket(version = 6)))
    }

    @Test
    fun `rejects a packet that does not carry udp`() {
        assertNull(Ipv4UdpCodec.parseIpv4Udp(buildPacket(protocol = 6)))
    }

    @Test
    fun `rejects a packet with a broken ipv4 checksum`() {
        assertNull(Ipv4UdpCodec.parseIpv4Udp(buildPacket(validIpChecksum = false)))
    }

    @Test
    fun `rejects a packet with a broken udp checksum`() {
        assertNull(Ipv4UdpCodec.parseIpv4Udp(buildPacket(validUdpChecksum = false)))
    }

    @Test
    fun `rejects a truncated packet`() {
        val packet = buildPacket()
        val truncated = packet.copyOfRange(0, packet.size - 4)

        assertNull(Ipv4UdpCodec.parseIpv4Udp(truncated))
    }

    @Test
    fun `rejects a fragmented packet`() {
        assertNull(Ipv4UdpCodec.parseIpv4Udp(buildPacket(fragmentOffset = 0x0020)))
    }

    @Test
    fun `rejects a packet whose total length exceeds the buffer`() {
        val packet = buildPacket()
        writeU16(packet, 2, packet.size + 40)

        assertNull(Ipv4UdpCodec.parseIpv4Udp(packet))
    }

    @Test
    fun `validates the ipv4 header checksum`() {
        val packet = buildPacket()

        assertEquals(0, Ipv4UdpCodec.ipv4HeaderChecksum(packet, 20))
    }

    @Test
    fun `detects a wrong ipv4 header checksum`() {
        val packet = buildPacket(validIpChecksum = false)

        assertNotEquals(0, Ipv4UdpCodec.ipv4HeaderChecksum(packet, 20))
    }

    @Test
    fun `builds a response with swapped addresses and ports`() {
        val parsed = Ipv4UdpCodec.parseIpv4Udp(buildPacket())!!
        val response = Ipv4UdpCodec.buildIpv4UdpResponse(parsed, byteArrayOf(9, 9))

        val parsedResponse = Ipv4UdpCodec.parseIpv4Udp(response)

        assertNotNull(parsedResponse)
        assertEquals(0x0A000002, parsedResponse.sourceAddress)
        assertEquals(0x0A000001, parsedResponse.destinationAddress)
        assertEquals(53, parsedResponse.sourcePort)
        assertEquals(5353, parsedResponse.destinationPort)
    }

    @Test
    fun `built response carries a valid ipv4 checksum`() {
        val parsed = Ipv4UdpCodec.parseIpv4Udp(buildPacket())!!
        val response = Ipv4UdpCodec.buildIpv4UdpResponse(parsed, byteArrayOf(1, 2, 3))

        assertEquals(0, Ipv4UdpCodec.ipv4HeaderChecksum(response, 20))
    }

    @Test
    fun `built response carries a valid udp checksum`() {
        val parsed = Ipv4UdpCodec.parseIpv4Udp(buildPacket())!!
        val response = Ipv4UdpCodec.buildIpv4UdpResponse(parsed, byteArrayOf(1, 2, 3))

        assertNotNull(Ipv4UdpCodec.parseIpv4Udp(response))
    }

    @Test
    fun `built response round trips through the parser`() {
        val payload = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55)
        val parsed = Ipv4UdpCodec.parseIpv4Udp(buildPacket(payload = payload))!!
        val response = Ipv4UdpCodec.buildIpv4UdpResponse(parsed, payload)

        val parsedResponse = Ipv4UdpCodec.parseIpv4Udp(response)

        assertNotNull(parsedResponse)
        assertEquals(payload.size, parsedResponse.payload.size)
        for (index in payload.indices) {
            assertEquals(payload[index], parsedResponse.payload[index])
        }
    }

    @Test
    fun `built response preserves the identification and the ttl`() {
        val parsed = Ipv4UdpCodec.parseIpv4Udp(buildPacket())!!
        val response = Ipv4UdpCodec.buildIpv4UdpResponse(parsed, byteArrayOf(7))

        val parsedResponse = Ipv4UdpCodec.parseIpv4Udp(response)

        assertNotNull(parsedResponse)
        assertEquals(parsed.identification, parsedResponse.identification)
        assertEquals(parsed.ttl, parsedResponse.ttl)
    }

    private fun buildPacket(
        source: Int = 0x0A000001,
        destination: Int = 0x0A000002,
        sourcePort: Int = 5353,
        destinationPort: Int = 53,
        payload: ByteArray = byteArrayOf(0x01, 0x02, 0x03, 0x04),
        protocol: Int = 17,
        version: Int = 4,
        fragmentOffset: Int = 0,
        validIpChecksum: Boolean = true,
        validUdpChecksum: Boolean = true,
    ): ByteArray {
        val udpLength = 8 + payload.size
        val packet = ByteArray(20 + udpLength)

        packet[0] = ((version shl 4) or 5).toByte()
        packet[1] = 0
        writeU16(packet, 2, packet.size)
        writeU16(packet, 4, 0x1234)
        writeU16(packet, 6, fragmentOffset)
        packet[8] = 64
        packet[9] = protocol.toByte()
        writeU32(packet, 12, source)
        writeU32(packet, 16, destination)

        val ipChecksum = checksum(packet, 0, 20)
        writeU16(packet, 10, if (validIpChecksum) ipChecksum else ipChecksum xor 0xFFFF)

        writeU16(packet, 20, sourcePort)
        writeU16(packet, 22, destinationPort)
        writeU16(packet, 24, udpLength)
        writeU16(packet, 26, 0)
        payload.copyInto(packet, 28)

        val udp = udpChecksum(packet, 20, udpLength)
        writeU16(packet, 26, if (validUdpChecksum) udp else udp xor 0xFFFF)

        return packet
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var index = offset
        val end = offset + length

        while (index + 1 < end) {
            sum += ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) {
            sum += (data[index].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }

        return (sum and 0xFFFF) xor 0xFFFF
    }

    private fun udpChecksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        sum += ((packet[12].toInt() and 0xFF) shl 8) or (packet[13].toInt() and 0xFF)
        sum += ((packet[14].toInt() and 0xFF) shl 8) or (packet[15].toInt() and 0xFF)
        sum += ((packet[16].toInt() and 0xFF) shl 8) or (packet[17].toInt() and 0xFF)
        sum += packet[9].toInt() and 0xFF
        sum += length

        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += ((packet[index].toInt() and 0xFF) shl 8) or (packet[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) {
            sum += (packet[index].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }

        val folded = (sum and 0xFFFF) xor 0xFFFF
        return if (folded == 0) 0xFFFF else folded
    }

    private fun writeU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 24) and 0xFF).toByte()
        packet[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        packet[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 3] = (value and 0xFF).toByte()
    }
}
