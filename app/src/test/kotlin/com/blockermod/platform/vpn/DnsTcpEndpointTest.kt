package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.frameDnsTcp
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Builds real IPv4/TCP packets for the DNS TCP endpoint; no Android or socket required. */
class DnsTcpEndpointTest {

    private val responses = ByteArrayOutputStream()

    private val endpoint = DnsTcpEndpoint(
        writePacket = { responses.write(it) },
        resolve = { query -> DnsCodec.buildNxDomain(DnsCodec.parseQuery(query)!!) },
    )

    @Test
    fun `syn is answered with syn ack`() {
        endpoint.handle(seg(1L, flags = Ipv4TcpCodec.Flags.SYN))

        val reply = Ipv4TcpCodec.parse(responses.toByteArray())!!
        assertEquals((Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK), reply.flags)
        assertEquals(2L, reply.acknowledgmentNumber)
        assertEquals(1, endpoint.connectionCount())
    }

    @Test
    fun `a dns message split across segments is answered once`() {
        handshake()
        val framed = frameDnsTcp(DnsWire.buildQuery(0x42, "blocked.example", 1))

        endpoint.handle(seg(2L, framed.copyOfRange(0, 1)))
        endpoint.handle(seg(3L, framed.copyOfRange(1, 2)))
        endpoint.handle(seg(4L, framed.copyOfRange(2, framed.size)))

        assertEquals(1, countAnswers(), "one answer per complete query")
        // The response is a DNS answer (QR set): assert its ID from the raw header, not via
        // parseQuery which (correctly) rejects responses.
        val answer = payloadOfLastDataSegment()
        assertEquals(0x42, ((answer[0].toInt() and 0xFF) shl 8) or (answer[1].toInt() and 0xFF))
    }

    @Test
    fun `two queries in one tcp segment produce two answers`() {
        handshake()
        val first = frameDnsTcp(DnsWire.buildQuery(1, "a.example", 1))
        val second = frameDnsTcp(DnsWire.buildQuery(2, "b.example", 1))

        endpoint.handle(seg(2L, first + second))

        assertEquals(2, countAnswers())
    }

    @Test
    fun `duplicate segment is not answered twice`() {
        handshake()
        val framed = frameDnsTcp(DnsWire.buildQuery(7, "dup.example", 1))

        endpoint.handle(seg(2L, framed))
        endpoint.handle(seg(2L, framed))

        assertEquals(1, countAnswers())
    }

    @Test
    fun `idle half open connection is reaped`() {
        var now = 0L
        val endpoint = DnsTcpEndpoint(
            writePacket = {},
            resolve = { ByteArray(12) },
            nowMillis = { now },
        )
        endpoint.handle(seg(1L, flags = Ipv4TcpCodec.Flags.SYN))
        assertEquals(1, endpoint.connectionCount())

        now = 70_000L
        endpoint.handle(seg(2L, flags = Ipv4TcpCodec.Flags.SYN, port = 40_001))

        assertEquals(1, endpoint.connectionCount())
    }

    @Test
    fun `rst removes the connection`() {
        handshake()

        endpoint.handle(seg(2L, flags = Ipv4TcpCodec.Flags.RST))

        assertEquals(0, endpoint.connectionCount())
    }

    private fun handshake() {
        responses.reset()
        endpoint.closeAll()
        endpoint.handle(seg(1L, flags = Ipv4TcpCodec.Flags.SYN))
        responses.reset()
    }

    private fun countAnswers(): Int {
        var offset = 0
        var count = 0
        val bytes = responses.toByteArray()
        while (offset < bytes.size) {
            val packet = Ipv4TcpCodec.parse(bytes.copyOfRange(offset, bytes.size)) ?: break
            val consumed = packet.ipHeaderLength + 20 + packet.payload.size
            if (packet.flags and Ipv4TcpCodec.Flags.PSH != 0) count++
            offset += consumed
        }
        return count
    }

    private fun payloadOfLastDataSegment(): ByteArray {
        val bytes = responses.toByteArray()
        var offset = 0
        var last = ByteArray(0)
        while (offset < bytes.size) {
            val packet = Ipv4TcpCodec.parse(bytes.copyOfRange(offset, bytes.size)) ?: break
            if (packet.payload.isNotEmpty()) last = packet.payload.copyOfRange(2, packet.payload.size)
            offset += packet.ipHeaderLength + 20 + packet.payload.size
        }
        return last
    }

    private fun seg(
        seq: Long,
        payload: ByteArray = ByteArray(0),
        flags: Int = Ipv4TcpCodec.Flags.ACK,
        port: Int = 53,
    ): Ipv4TcpPacket = Ipv4TcpPacket(
        sourceAddress = 0x0A000001,
        destinationAddress = 0x0A000003,
        sourcePort = 40000,
        destinationPort = port,
        sequenceNumber = seq,
        acknowledgmentNumber = 0L,
        flags = flags,
        window = 65535,
        payload = payload,
        identification = 1,
        ttl = 64,
        tcpHeaderLength = 20,
    )
}
