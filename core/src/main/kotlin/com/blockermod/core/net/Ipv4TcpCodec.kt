package com.blockermod.core.net

/**
 * A parsed IPv4 datagram carrying a TCP segment.
 *
 * @property sourceAddress raw IPv4 source address in network byte order.
 * @property destinationAddress raw IPv4 destination address in network byte order.
 * @property sourcePort TCP source port.
 * @property destinationPort TCP destination port.
 * @property sequenceNumber current sequence number.
 * @property acknowledgmentNumber current acknowledgment number.
 * @property flags TCP flag bits (see [Flags]).
 * @property window advertised receive window.
 * @property payload TCP payload bytes (after the TCP header, before any TCP options payload).
 * @property identification IPv4 identification field.
 * @property ttl IPv4 time to live.
 * @property tcpHeaderLength length of the TCP header in bytes, including options.
 */
class Ipv4TcpPacket(
    val sourceAddress: Int,
    val destinationAddress: Int,
    val sourcePort: Int,
    val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgmentNumber: Long,
    val flags: Int,
    val window: Int,
    val payload: ByteArray,
    val identification: Int,
    val ttl: Int,
    val tcpHeaderLength: Int,
    val ipHeaderLength: Int = 20,
)

/**
 * Pure IPv4/TCP codec for packets that travel inside a DNS/firewall VPN tunnel.
 *
 * The codec never throws: packets that are not IPv4, not TCP, truncated, or carrying a broken IPv4
 * header checksum are rejected with null. TCP checksums are computed for generated packets; inbound
 * checksum validation is left to the relay because hardware offload may leave it zero.
 */
object Ipv4TcpCodec {

    /** TCP flag bits. */
    object Flags {
        const val FIN: Int = 1
        const val SYN: Int = 2
        const val RST: Int = 4
        const val PSH: Int = 8
        const val ACK: Int = 16
        const val URG: Int = 32
    }

    private const val IPV4_HEADER_SIZE: Int = 20
    private const val MIN_TCP_HEADER_SIZE: Int = 20
    private const val PROTOCOL_TCP: Int = 6

    /** Parses an IPv4/TCP packet, or returns null for anything malformed. */
    fun parse(packet: ByteArray): Ipv4TcpPacket? {
        if (packet.size < IPV4_HEADER_SIZE + MIN_TCP_HEADER_SIZE) return null

        val version = (packet[0].toInt() and 0xF0) ushr 4
        if (version != 4) return null

        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (ipHeaderLength < IPV4_HEADER_SIZE) return null
        if (packet.size < ipHeaderLength + MIN_TCP_HEADER_SIZE) return null

        val totalLength = readU16(packet, 2)
        if (totalLength < ipHeaderLength + MIN_TCP_HEADER_SIZE || totalLength > packet.size) return null

        val fragmentOffset = readU16(packet, 6) and 0x1FFF
        if (fragmentOffset != 0) return null
        if (packet[9].toInt() and 0xFF != PROTOCOL_TCP) return null
        if (Ipv4UdpCodec.ipv4HeaderChecksum(packet, ipHeaderLength) != 0) return null

        val tcpOffset = ipHeaderLength
        val sourcePort = readU16(packet, tcpOffset)
        val destinationPort = readU16(packet, tcpOffset + 2)
        val sequenceNumber = readU32(packet, tcpOffset + 4)
        val acknowledgmentNumber = readU32(packet, tcpOffset + 8)
        val tcpHeaderLength = ((packet[tcpOffset + 12].toInt() and 0xF0) ushr 4) * 4
        if (tcpHeaderLength < MIN_TCP_HEADER_SIZE) return null
        if (tcpOffset + tcpHeaderLength > totalLength) return null

        val flags = packet[tcpOffset + 13].toInt() and 0x3F
        val window = readU16(packet, tcpOffset + 14)
        val payload = packet.copyOfRange(tcpOffset + tcpHeaderLength, tcpOffset + (totalLength - ipHeaderLength))

        return Ipv4TcpPacket(
            sourceAddress = readU32(packet, 12).toInt(),
            destinationAddress = readU32(packet, 16).toInt(),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            sequenceNumber = sequenceNumber,
            acknowledgmentNumber = acknowledgmentNumber,
            flags = flags,
            window = window,
            payload = payload,
            identification = readU16(packet, 4),
            ttl = packet[8].toInt() and 0xFF,
            tcpHeaderLength = tcpHeaderLength,
            ipHeaderLength = ipHeaderLength,
        )
    }

    /**
     * Builds an IPv4/TCP packet with swapped endpoints and the given sequence/ack/window/flags.
     * [options] are placed in the TCP header after the fixed 20 bytes.
     */
    fun build(
        request: Ipv4TcpPacket,
        payload: ByteArray,
        sequenceNumber: Long,
        acknowledgmentNumber: Long,
        flags: Int,
        window: Int = DEFAULT_WINDOW,
        options: ByteArray = EMPTY,
        identification: Int = request.identification + 1,
        ttl: Int = request.ttl,
    ): ByteArray {
        val tcpHeaderLength = MIN_TCP_HEADER_SIZE + options.size
        val tcpLength = tcpHeaderLength + payload.size
        val totalLength = IPV4_HEADER_SIZE + tcpLength
        val out = ByteArray(totalLength)

        out[0] = 0x45
        out[1] = 0
        writeU16(out, 2, totalLength)
        writeU16(out, 4, identification)
        writeU16(out, 6, 0x4000) // Don't fragment
        out[8] = ttl.toByte()
        out[9] = PROTOCOL_TCP.toByte()
        writeU32(out, 12, request.destinationAddress.toLong() and 0xFFFFFFFFL)
        writeU32(out, 16, request.sourceAddress.toLong() and 0xFFFFFFFFL)
        writeU16(out, 10, computeIpv4HeaderChecksum(out, IPV4_HEADER_SIZE))

        val tcp = IPV4_HEADER_SIZE
        writeU16(out, tcp, request.destinationPort)
        writeU16(out, tcp + 2, request.sourcePort)
        writeU32(out, tcp + 4, sequenceNumber)
        writeU32(out, tcp + 8, acknowledgmentNumber)
        out[tcp + 12] = ((tcpHeaderLength / 4) shl 4).toByte()
        out[tcp + 13] = (flags and 0x3F).toByte()
        writeU16(out, tcp + 14, window)
        writeU16(out, tcp + 16, 0) // checksum placeholder
        writeU16(out, tcp + 18, 0) // urgent pointer
        options.copyInto(out, tcp + MIN_TCP_HEADER_SIZE)
        payload.copyInto(out, tcp + tcpHeaderLength)

        val checksum = computeTcpChecksum(
            sourceAddress = request.destinationAddress,
            destinationAddress = request.sourceAddress,
            tcp = out,
            tcpOffset = tcp,
            tcpLength = tcpLength,
        )
        writeU16(out, tcp + 16, checksum)
        return out
    }

    /** MSS option (kind 2, length 4, value [value]) for a SYN/SYN-ACK. */
    fun mssOption(value: Int): ByteArray = byteArrayOf(2, 4, (value ushr 8).toByte(), value.toByte())

    /** A RST packet closing the connection in the given direction. */
    fun reset(request: Ipv4TcpPacket): ByteArray = build(
        request = request,
        payload = EMPTY,
        sequenceNumber = 0L,
        acknowledgmentNumber = request.sequenceNumber + 1L,
        flags = Flags.RST or Flags.ACK,
    )

    private fun computeTcpChecksum(
        sourceAddress: Int,
        destinationAddress: Int,
        tcp: ByteArray,
        tcpOffset: Int,
        tcpLength: Int,
    ): Int {
        var sum = 0
        val src = sourceAddress.toLong() and 0xFFFFFFFFL
        val dst = destinationAddress.toLong() and 0xFFFFFFFFL
        sum += (src ushr 16).toInt()
        sum += (src and 0xFFFFL).toInt()
        sum += (dst ushr 16).toInt()
        sum += (dst and 0xFFFFL).toInt()
        sum += PROTOCOL_TCP
        sum += tcpLength and 0xFFFF

        var index = tcpOffset
        val end = tcpOffset + tcpLength
        while (index + 1 < end) {
            sum += ((tcp[index].toInt() and 0xFF) shl 8) or (tcp[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) sum += (tcp[index].toInt() and 0xFF) shl 8

        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        val folded = (sum and 0xFFFF).inv() and 0xFFFF
        return if (folded == 0) 0xFFFF else folded
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
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum and 0xFFFF).inv() and 0xFFFF
    }

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)

    private fun readU32(packet: ByteArray, offset: Int): Long =
        ((packet[offset].toLong() and 0xFF) shl 24) or
            ((packet[offset + 1].toLong() and 0xFF) shl 16) or
            ((packet[offset + 2].toLong() and 0xFF) shl 8) or
            (packet[offset + 3].toLong() and 0xFF)

    private fun writeU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(packet: ByteArray, offset: Int, value: Long) {
        packet[offset] = ((value ushr 24) and 0xFF).toByte()
        packet[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        packet[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 3] = (value and 0xFF).toByte()
    }

    private val EMPTY = ByteArray(0)
    private const val DEFAULT_WINDOW: Int = 65535
}
