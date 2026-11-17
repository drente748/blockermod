package com.blockermod.core.net

/**
 * A parsed IPv4 datagram carrying a UDP payload.
 *
 * @property sourceAddress raw IPv4 source address in network byte order.
 * @property destinationAddress raw IPv4 destination address in network byte order.
 * @property sourcePort UDP source port.
 * @property destinationPort UDP destination port.
 * @property payload UDP payload bytes.
 * @property identification IPv4 identification field.
 * @property ttl IPv4 time to live.
 * @property ipHeaderLength length of the IPv4 header in bytes, including options.
 */
class Ipv4UdpPacket(
    val sourceAddress: Int,
    val destinationAddress: Int,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
    val identification: Int,
    val ttl: Int,
    val ipHeaderLength: Int,
)

/**
 * Pure IPv4 and UDP codec for packets that travel inside a VPN tunnel.
 *
 * The codec never throws. Packets that are not IPv4, not UDP, fragmented, truncated, or carrying a
 * broken header checksum are rejected with null.
 */
object Ipv4UdpCodec {

    /** Size of an IPv4 header without options. */
    private const val IPV4_HEADER_SIZE: Int = 20

    /** Size of a UDP header. */
    private const val UDP_HEADER_SIZE: Int = 8

    /** IP protocol number of UDP. */
    private const val PROTOCOL_UDP: Int = 17

    /** IPv4 version carried by the header. */
    private const val IPV4_VERSION: Int = 4

    /**
     * Parses an IPv4 datagram carrying UDP.
     *
     * Returns null when the packet is not IPv4, does not carry UDP, is fragmented, is truncated, or
     * fails the IPv4 header checksum validation.
     */
    fun parseIpv4Udp(packet: ByteArray): Ipv4UdpPacket? {
        if (packet.size < IPV4_HEADER_SIZE + UDP_HEADER_SIZE) return null

        val version = (packet[0].toInt() and 0xF0) ushr 4
        if (version != IPV4_VERSION) return null

        val headerLength = (packet[0].toInt() and 0x0F) * 4
        if (headerLength < IPV4_HEADER_SIZE) return null
        if (packet.size < headerLength + UDP_HEADER_SIZE) return null

        val totalLength = readU16(packet, 2)
        if (totalLength < headerLength + UDP_HEADER_SIZE) return null
        if (totalLength > packet.size) return null

        // MF (0x2000) or a non-zero offset: DNS policy must see a whole datagram, never a fragment
        // (this tunnel does no reassembly) — reject even the first fragment (B6).
        if (readU16(packet, 6) and 0x3FFF != 0) return null

        if (packet[9].toInt() != PROTOCOL_UDP) return null
        if (ipv4HeaderChecksum(packet, headerLength) != 0) return null

        val udpOffset = headerLength
        val sourcePort = readU16(packet, udpOffset)
        val destinationPort = readU16(packet, udpOffset + 2)
        val udpLength = readU16(packet, udpOffset + 4)
        val udpChecksum = readU16(packet, udpOffset + 6)

        if (udpLength < UDP_HEADER_SIZE) return null
        if (udpOffset + udpLength > totalLength) return null

        if (udpChecksum != 0 && udpChecksumSum(packet, udpOffset, udpLength) != 0xFFFF) return null

        val payload = packet.copyOfRange(udpOffset + UDP_HEADER_SIZE, udpOffset + udpLength)

        return Ipv4UdpPacket(
            sourceAddress = readU32(packet, 12),
            destinationAddress = readU32(packet, 16),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            payload = payload,
            identification = readU16(packet, 4),
            ttl = packet[8].toInt() and 0xFF,
            ipHeaderLength = headerLength,
        )
    }

    /**
     * Builds the IPv4 and UDP datagram that answers the given packet with the given payload.
     *
     * Addresses and ports are swapped, the identification field is preserved, and both the IPv4
     * header checksum and the UDP checksum are computed correctly.
     */
    fun buildIpv4UdpResponse(packet: Ipv4UdpPacket, payload: ByteArray): ByteArray {
        val totalLength = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + payload.size
        val out = ByteArray(totalLength)

        out[0] = 0x45
        out[1] = 0
        writeU16(out, 2, totalLength)
        writeU16(out, 4, packet.identification)
        writeU16(out, 6, 0x4000)
        out[8] = packet.ttl.toByte()
        out[9] = PROTOCOL_UDP.toByte()
        writeU32(out, 12, packet.destinationAddress)
        writeU32(out, 16, packet.sourceAddress)

        writeU16(out, 10, computeIpv4HeaderChecksum(out, IPV4_HEADER_SIZE))

        val udpOffset = IPV4_HEADER_SIZE
        writeU16(out, udpOffset, packet.destinationPort)
        writeU16(out, udpOffset + 2, packet.sourcePort)
        writeU16(out, udpOffset + 4, UDP_HEADER_SIZE + payload.size)
        writeU16(out, udpOffset + 6, 0)
        payload.copyInto(out, udpOffset + UDP_HEADER_SIZE)

        writeU16(out, udpOffset + 6, computeUdpChecksum(out, udpOffset, UDP_HEADER_SIZE + payload.size))

        return out
    }

    /**
     * Validates the IPv4 header checksum of a packet.
     *
     * Returns zero when the checksum is correct and a non zero value otherwise.
     */
    fun ipv4HeaderChecksum(packet: ByteArray, headerLength: Int): Int {
        if (headerLength < IPV4_HEADER_SIZE || packet.size < headerLength) return -1

        var sum = 0
        var offset = 0
        while (offset + 1 < headerLength) {
            sum += ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
            offset += 2
        }
        if (offset < headerLength) {
            sum += (packet[offset].toInt() and 0xFF) shl 8
        }

        return if (fold(sum) == 0xFFFF) 0 else fold(sum)
    }

    private fun computeIpv4HeaderChecksum(packet: ByteArray, headerLength: Int): Int {
        var sum = 0
        var offset = 0
        while (offset + 1 < headerLength) {
            if (offset != 10) {
                sum += ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
            }
            offset += 2
        }
        if (offset < headerLength) {
            sum += (packet[offset].toInt() and 0xFF) shl 8
        }

        return fold(sum) xor 0xFFFF
    }

    private fun udpChecksumSum(packet: ByteArray, udpOffset: Int, udpLength: Int): Int {
        var sum = 0

        sum += (packet[12].toInt() and 0xFF) shl 8
        sum += packet[13].toInt() and 0xFF
        sum += (packet[14].toInt() and 0xFF) shl 8
        sum += packet[15].toInt() and 0xFF
        sum += (packet[16].toInt() and 0xFF) shl 8
        sum += packet[17].toInt() and 0xFF
        sum += PROTOCOL_UDP
        sum += udpLength

        var offset = udpOffset
        val end = udpOffset + udpLength
        while (offset + 1 < end) {
            sum += ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
            offset += 2
        }
        if (offset < end) {
            sum += (packet[offset].toInt() and 0xFF) shl 8
        }

        return fold(sum)
    }

    private fun computeUdpChecksum(packet: ByteArray, udpOffset: Int, udpLength: Int): Int {
        val checksum = udpChecksumSum(packet, udpOffset, udpLength)
        val folded = checksum xor 0xFFFF
        return if (folded == 0) 0xFFFF else folded
    }

    private fun fold(sum: Int): Int {
        var value = sum
        while ((value ushr 16) != 0) {
            value = (value and 0xFFFF) + (value ushr 16)
        }
        return value and 0xFFFF
    }

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)

    private fun readU32(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 24) or
            ((packet[offset + 1].toInt() and 0xFF) shl 16) or
            ((packet[offset + 2].toInt() and 0xFF) shl 8) or
            (packet[offset + 3].toInt() and 0xFF)

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
