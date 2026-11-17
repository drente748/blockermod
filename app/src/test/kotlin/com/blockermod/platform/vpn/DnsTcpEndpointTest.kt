package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsTcpFramer
import com.blockermod.core.dns.frameDnsTcp
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Builds real IPv4/TCP packets for the DNS TCP endpoint. A genuine three-way handshake is performed
 * before any data packet: the server ISN is learned from the SYN-ACK so ACK numbers are correct.
 */
class DnsTcpEndpointTest {

    private val responses = ByteArrayOutputStream()
    private val clientIsn = 1000L
    private var serverIsn = 0L

    private val endpoint = DnsTcpEndpoint(
        writePacket = { responses.write(it) },
        resolve = { query -> DnsCodec.buildNxDomain(DnsCodec.parseQuery(query)!!) },
    )

    /** Performs SYN -> SYN-ACK -> ACK and leaves [responses] empty for the assertion. */
    private fun handshake(mss: Int = 0) {
        endpoint.closeAll()
        responses.reset()
        endpoint.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN, mss = mss))
        val synAck = Ipv4TcpCodec.parse(responses.toByteArray())!!
        assertTrue(synAck.flags and Ipv4TcpCodec.Flags.SYN != 0)
        serverIsn = synAck.sequenceNumber
        responses.reset()
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, flags = Ipv4TcpCodec.Flags.ACK))
        responses.reset()
        assertEquals(1, endpoint.connectionCount(), "handshake must establish the connection")
    }

    @Test
    fun `syn is answered with syn ack advertising our mss`() {
        endpoint.closeAll()
        responses.reset()
        endpoint.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN, mss = 1200))

        val reply = Ipv4TcpCodec.parse(responses.toByteArray())!!
        assertEquals(Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK, reply.flags)
        assertEquals((clientIsn + 1) and SEQ, reply.acknowledgmentNumber)
        // Our SYN-ACK advertises our own receive MSS (1460), not the client's value.
        assertEquals(1460, Ipv4TcpCodec.effectiveMss(reply))
        assertEquals(1, endpoint.connectionCount())
    }

    @Test
    fun `ack with wrong number is reset and connection closed`() {
        endpoint.closeAll()
        responses.reset()
        endpoint.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN))
        val synAck = Ipv4TcpCodec.parse(responses.toByteArray())!!
        serverIsn = synAck.sequenceNumber
        responses.reset()

        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 2) and SEQ, flags = Ipv4TcpCodec.Flags.ACK))

        assertEquals(0, endpoint.connectionCount())
        assertTrue(parseAll().any { it.flags and Ipv4TcpCodec.Flags.RST != 0 })
    }

    @Test
    fun `the third ack may carry the first query`() {
        endpoint.closeAll()
        responses.reset()
        endpoint.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN))
        val synAck = Ipv4TcpCodec.parse(responses.toByteArray())!!
        serverIsn = synAck.sequenceNumber
        responses.reset()

        // TCP permits data on the handshake-completing ACK; resetting it would lose the query (B4).
        val framed = frameDnsTcp(DnsWire.buildQuery(0x51, "early.example", 1))
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ,
            flags = Ipv4TcpCodec.Flags.ACK or Ipv4TcpCodec.Flags.PSH, payload = framed))

        assertEquals(1, framedMessages().size, "the query on the third ACK must be answered")
        assertTrue(parseAll().none { it.flags and Ipv4TcpCodec.Flags.RST != 0 })
        assertEquals(1, endpoint.connectionCount())
    }

    @Test
    fun `data before completing handshake is reset`() {
        endpoint.closeAll()
        responses.reset()
        endpoint.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN))
        responses.reset()

        endpoint.handle(seg(clientIsn + 1, ack = 0L, flags = Ipv4TcpCodec.Flags.ACK,
            payload = frameDnsTcp(DnsWire.buildQuery(1, "x.example", 1))))

        assertEquals(0, endpoint.connectionCount())
        assertTrue(parseAll().any { it.flags and Ipv4TcpCodec.Flags.RST != 0 })
    }

    @Test
    fun `a dns message split across segments is answered once`() {
        handshake()
        val framed = frameDnsTcp(DnsWire.buildQuery(0x42, "blocked.example", 1))

        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = framed.copyOfRange(0, 1)))
        endpoint.handle(seg(clientIsn + 2, ack = (serverIsn + 1) and SEQ, payload = framed.copyOfRange(1, 2)))
        endpoint.handle(seg(clientIsn + 3, ack = (serverIsn + 1) and SEQ, payload = framed.copyOfRange(2, framed.size)))

        assertEquals(1, framedMessages().size, "one answer per complete query")
        val answer = framedMessages().single()
        assertEquals(0x42, ((answer[0].toInt() and 0xFF) shl 8) or (answer[1].toInt() and 0xFF))
    }

    @Test
    fun `a message split byte by byte is answered once`() {
        handshake()
        val framed = frameDnsTcp(DnsWire.buildQuery(0x43, "bytes.example", 1))
        framed.forEachIndexed { index, byte ->
            endpoint.handle(seg(clientIsn + 1 + index, ack = (serverIsn + 1) and SEQ, payload = byteArrayOf(byte)))
        }

        assertEquals(1, framedMessages().size)
    }

    @Test
    fun `two queries in one tcp segment produce two answers`() {
        handshake()
        val first = frameDnsTcp(DnsWire.buildQuery(1, "a.example", 1))
        val second = frameDnsTcp(DnsWire.buildQuery(2, "b.example", 1))

        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = first + second))

        assertEquals(2, framedMessages().size)
    }

    @Test
    fun `duplicate segment is not answered twice once the answer is acknowledged`() {
        handshake()
        val framed = frameDnsTcp(DnsWire.buildQuery(7, "dup.example", 1))

        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = framed))
        acknowledgeAllAnswers(clientIsn + 1 + framed.size)
        responses.reset()

        // Once nothing is outstanding, a retransmitted query must not re-answer.
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = framed))
        assertEquals(0, framedMessages().size)
    }

    @Test
    fun `client retransmitted query triggers answer retransmission`() {
        handshake()
        val framed = frameDnsTcp(DnsWire.buildQuery(17, "lost.example", 1))

        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = framed))
        assertEquals(1, framedMessages().size)

        // The client retries the same query at the old sequence: the unacknowledged answer must be
        // re-sent so the client is not left without a response.
        responses.reset()
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = framed))
        assertEquals(1, framedMessages().size, "the answer must be retransmitted")
    }

    @Test
    fun `out of order segment does not produce an answer`() {
        handshake()
        val framed = frameDnsTcp(DnsWire.buildQuery(8, "gap.example", 1))

        // A segment at seq+10 creates a gap: no answer until the missing bytes arrive.
        endpoint.handle(seg(clientIsn + 11, ack = (serverIsn + 1) and SEQ, payload = framed))
        assertEquals(0, framedMessages().size)

        // Fill the gap with the correct bytes at the expected sequence.
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = framed))
        assertEquals(1, framedMessages().size)
    }

    @Test
    fun `large response is split into mss segments with correct sequence numbers`() {
        // Use a large resolver answer so the framed response exceeds the client's small MSS.
        val bigEndpoint = DnsTcpEndpoint(
            writePacket = { responses.write(it) },
            resolve = { ByteArray(3000) { (it and 0xFF).toByte() }.also { it[0] = 0; it[1] = 5 } },
        )
        // Manual handshake against bigEndpoint.
        responses.reset()
        bigEndpoint.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN, mss = 1200))
        val synAck = Ipv4TcpCodec.parse(responses.toByteArray())!!
        val isn = synAck.sequenceNumber
        responses.reset()
        bigEndpoint.handle(seg(clientIsn + 1, ack = (isn + 1) and SEQ, flags = Ipv4TcpCodec.Flags.ACK))
        responses.reset()

        val query = frameDnsTcp(DnsWire.buildQuery(9, "big.example", 1))
        bigEndpoint.handle(seg(clientIsn + 1, ack = (isn + 1) and SEQ, payload = query))

        val data = parseAll().filter { it.flags and Ipv4TcpCodec.Flags.PSH != 0 }
        assertTrue(data.size >= 3, "3002-byte framed response must span at least 3 segments")
        assertTrue(data.all { it.payload.size <= 1200 }, "each segment must respect client MSS=1200")
        // Sequence numbers advance by the previous segment's payload length.
        var expectedSeq = (isn + 1) and SEQ
        data.forEach { segment ->
            assertEquals(expectedSeq, segment.sequenceNumber)
            expectedSeq = (expectedSeq + segment.payload.size.toLong()) and SEQ
        }
        // Reassembly yields exactly the framed response that was sent.
        val rebuilt = data.sortedBy { it.sequenceNumber }.flatMap { it.payload.asList() }.toByteArray()
        assertEquals(3000 + 2, rebuilt.size)
    }

    @Test
    fun `response over 64KiB of cumulative queries does not stall the connection`() {
        val cumulative = DnsTcpEndpoint(
            writePacket = { responses.write(it) },
            resolve = { DnsCodec.buildNxDomain(DnsCodec.parseQuery(it)!!) },
        )
        responses.reset()
        cumulative.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN))
        val synAck = Ipv4TcpCodec.parse(responses.toByteArray())!!
        val isn = synAck.sequenceNumber
        responses.reset()
        cumulative.handle(seg(clientIsn + 1, ack = (isn + 1) and SEQ, flags = Ipv4TcpCodec.Flags.ACK))
        responses.reset()

        // ~270-byte queries so ~70 KiB of inbound stream takes ~265 queries, not thousands.
        // Four 60-char labels keep the total DNS name length under the 255-byte wire limit.
        val longName = (1..4).joinToString(".") { "a".repeat(60) }
        val query = frameDnsTcp(DnsWire.buildQuery(11, longName, 1))
        val framedAnswer = frameDnsTcp(DnsCodec.buildNxDomain(DnsCodec.parseQuery(
            DnsWire.buildQuery(11, longName, 1))!!))
        var seq = clientIsn + 1
        var totalSent = 0L
        var answers = 0
        var ackedServerBytes = 0L
        while (totalSent < 70 * 1024) {
            cumulative.handle(seg(seq, ack = (isn + 1 + ackedServerBytes) and SEQ, payload = query))
            seq += query.size
            totalSent += query.size
            answers++
            // A real client ACKs each answer so the window slides; this lets us keep sending and
            // proves the inbound stream never stalls past 64 KiB.
            ackedServerBytes += framedAnswer.size
        }
        assertEquals(answers, framedMessages().size, "every query answered despite >64 KiB of stream")
        assertEquals(1, cumulative.connectionCount(), "connection must remain open")
    }

    @Test
    fun `idle half open connection is reaped`() {
        var now = 0L
        val idle = DnsTcpEndpoint(writePacket = {}, resolve = { ByteArray(12) }, nowMillis = { now })
        idle.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN))
        assertEquals(1, idle.connectionCount())

        now = 70_000L
        idle.handle(seg(clientIsn, flags = Ipv4TcpCodec.Flags.SYN, port = 40_001))
        assertEquals(1, idle.connectionCount())
    }

    @Test
    fun `rst removes the connection`() {
        handshake()
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, flags = Ipv4TcpCodec.Flags.RST))
        assertEquals(0, endpoint.connectionCount())
    }

    @Test
    fun `fin is deferred until response data is acknowledged`() {
        // Client sends a query and then FIN before acknowledging the answer.
        handshake()
        val query = frameDnsTcp(DnsWire.buildQuery(12, "fin.example", 1))
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = query))
        val data = parseAll().filter { it.flags and Ipv4TcpCodec.Flags.PSH != 0 }
        assertTrue(data.isNotEmpty())

        responses.reset()
        endpoint.handle(seg(clientIsn + 1 + query.size, ack = (serverIsn + 1) and SEQ,
            flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK))
        assertEquals(0, parseAll().count { it.flags and Ipv4TcpCodec.Flags.FIN != 0 },
            "no FIN while answer bytes are unacknowledged")
        assertEquals(1, endpoint.connectionCount())

        // Acknowledge the full answer; now FIN is sent and the flow enters LAST-ACK.
        val lastSeq = data.maxOf { it.sequenceNumber }
        val finalAck = (lastSeq + data.first { it.sequenceNumber == lastSeq }.payload.size.toLong()) and SEQ
        responses.reset()
        endpoint.handle(seg(clientIsn + 1 + query.size, ack = finalAck, flags = Ipv4TcpCodec.Flags.ACK))
        assertEquals(1, parseAll().count { it.flags and Ipv4TcpCodec.Flags.FIN != 0 })
        assertEquals(1, endpoint.connectionCount(), "LAST-ACK: stay until the client ACKs our FIN")

        // Extended regression (B4): the client's final ACK closes the flow without an RST.
        responses.reset()
        endpoint.handle(seg(clientIsn + 1 + query.size, ack = (finalAck + 1L) and SEQ,
            flags = Ipv4TcpCodec.Flags.ACK))
        assertEquals(0, parseAll().count { it.flags and Ipv4TcpCodec.Flags.RST != 0 },
            "the final ACK must be accepted, not reset")
        assertEquals(0, endpoint.connectionCount())
    }

    @Test
    fun `three duplicate acks retransmit unacknowledged answer`() {
        handshake()
        val query = frameDnsTcp(DnsWire.buildQuery(14, "dupack.example", 1))
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = query))
        assertEquals(1, framedMessages().size, "first answer sent")
        responses.reset()

        // Three pure duplicate ACKs (no forward progress) must trigger fast retransmit.
        repeat(3) {
            endpoint.handle(seg(clientIsn + 1 + query.size, ack = (serverIsn + 1) and SEQ,
                flags = Ipv4TcpCodec.Flags.ACK))
        }
        assertEquals(1, framedMessages().size, "duplicate ACKs must re-send the unacknowledged answer")
    }

    @Test
    fun `out of order fin does not close the connection before the query arrives`() {
        // A FIN that arrives before the in-flight DNS query (reordering) must not send our FIN or
        // drop the connection; the client will retransmit the query and we must still answer it.
        handshake()
        val query = frameDnsTcp(DnsWire.buildQuery(13, "reorder.example", 1))
        val finSeq = (clientIsn + 1 + query.size).toLong()

        // FIN at a sequence beyond what we have received: rejected by the stream, but must not close.
        endpoint.handle(seg(finSeq, ack = (serverIsn + 1) and SEQ,
            flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK))
        assertEquals(1, endpoint.connectionCount(), "out-of-order FIN must not close the connection")
        assertEquals(0, parseAll().count { it.flags and Ipv4TcpCodec.Flags.FIN != 0 },
            "no premature FIN from the server")

        // The retransmitted query still arrives and is answered.
        responses.reset()
        endpoint.handle(seg(clientIsn + 1, ack = (serverIsn + 1) and SEQ, payload = query))
        assertEquals(1, framedMessages().size)
        assertEquals(1, endpoint.connectionCount())
    }

    @Test
    fun `closeAll drops every connection`() {
        handshake()
        assertEquals(1, endpoint.connectionCount())
        endpoint.closeAll()
        assertEquals(0, endpoint.connectionCount())
    }

    private fun parseAll(): List<Ipv4TcpPacket> {
        val bytes = responses.toByteArray()
        val result = ArrayList<Ipv4TcpPacket>()
        var offset = 0
        while (offset < bytes.size) {
            val packet = Ipv4TcpCodec.parse(bytes.copyOfRange(offset, bytes.size)) ?: break
            result += packet
            offset += packet.ipHeaderLength + packet.tcpHeaderLength + packet.payload.size
        }
        return result
    }

    /** Sends a cumulative ACK covering every answer segment emitted so far. */
    private fun acknowledgeAllAnswers(nextClientSeq: Long) {
        val data = parseAll().filter { it.flags and Ipv4TcpCodec.Flags.PSH != 0 }
        if (data.isEmpty()) return
        val last = data.maxBy { it.sequenceNumber }
        val finalAck = (last.sequenceNumber + last.payload.size.toLong()) and SEQ
        endpoint.handle(seg(nextClientSeq, ack = finalAck, flags = Ipv4TcpCodec.Flags.ACK))
    }

    /** Reassembles all answer segments into framed DNS messages. */
    private fun framedMessages(): List<ByteArray> {
        val stream = parseAll()
            .filter { it.flags and Ipv4TcpCodec.Flags.PSH != 0 }
            .sortedBy { it.sequenceNumber }
            .flatMap { it.payload.asList() }
            .toByteArray()
        val framer = DnsTcpFramer()
        val out = ArrayList<ByteArray>()
        var offset = 0
        while (offset + 2 <= stream.size) {
            val length = ((stream[offset].toInt() and 0xFF) shl 8) or (stream[offset + 1].toInt() and 0xFF)
            if (length < 12 || offset + 2 + length > stream.size) break
            out += stream.copyOfRange(offset + 2, offset + 2 + length)
            offset += 2 + length
        }
        return out
    }

    private fun seg(
        seq: Long,
        ack: Long = 0L,
        payload: ByteArray = ByteArray(0),
        flags: Int = Ipv4TcpCodec.Flags.ACK,
        port: Int = 53,
        mss: Int = 0,
    ): Ipv4TcpPacket = Ipv4TcpPacket(
        sourceAddress = 0x0A000001,
        destinationAddress = 0x0A000003,
        sourcePort = 40_000,
        destinationPort = port,
        sequenceNumber = seq,
        acknowledgmentNumber = ack,
        flags = flags,
        window = 65_535,
        payload = payload,
        identification = 1,
        ttl = 64,
        tcpHeaderLength = 20,
        mss = mss,
    )

    private companion object {
        const val SEQ = 0xFFFFFFFFL
    }
}
