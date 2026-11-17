package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsTcpFramer
import com.blockermod.core.dns.frameDnsTcp
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import com.blockermod.core.net.TcpSendQueue
import com.blockermod.core.net.TcpStreamBuffer
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * DNS-only mode's TCP/53 endpoint.
 *
 * NOT a general TCP stack: it serves a local client's DNS-over-TCP connection, reassembles the inbound
 * byte stream, answers every framed query with the same [LocalDnsResolver] used by UDP, and closes
 * cleanly. General TCP is not captured in DNS-only mode (no default route).
 *
 * Reliability that matters for DNS is implemented without timers or extra threads (forbidden by the
 * project's battery contract): a three-way handshake is validated, outbound answers are split to the
 * client's MSS and held until acknowledged, duplicate/gap segments and duplicate ACKs trigger
 * retransmission, and FIN is deferred until every answer segment is acknowledged. A local TUN has no
 * real packet loss, so an RTO timer would only waste battery; retransmission is peer-driven.
 *
 * Memory is bounded in both directions: the inbound buffer is drained into the framer after every
 * accepted segment (so a long connection with many queries never accumulates processed bytes), and
 * the outbound queue has a fixed pending-byte cap.
 */
internal class DnsTcpEndpoint(
    private val writePacket: (ByteArray) -> Unit,
    private val resolve: (ByteArray) -> ByteArray?,
    private val maxConnections: Int = MAX_CONNECTIONS,
    private val idleTimeoutMillis: Long = 60_000L,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
) {

    private data class Key(
        val src: Int, val sport: Int, val dst: Int, val dport: Int,
    )

    private class Connection(
        val key: Key,
        val stream: TcpStreamBuffer = TcpStreamBuffer(),
        val framer: DnsTcpFramer = DnsTcpFramer(),
        val send: TcpSendQueue,
        val isn: Long,
        val clientIsn: Long,
        var request: Ipv4TcpPacket,
        var lastActivityMillis: Long,
        var established: Boolean = false, // three-way handshake completed
        var clientFin: Boolean = false,
        var ourFinSent: Boolean = false,
        var closed: Boolean = false,
        // Tracks the peer's ACK number in OUR sequence space (starts at SND.UNA = our ISN+1),
        // used only to detect duplicate ACKs for fast retransmit.
        var lastAck: Long = send.sndUna,
        var dupAckCount: Int = 0,
    )

    /** Number of live connections, exposed for tests. */
    fun connectionCount(): Int = connections.size

    private val connections = ConcurrentHashMap<Key, Connection>()
    private var lastReapMillis: Long = 0L

    /** Handles one IPv4/TCP packet addressed to the virtual DNS server. */
    fun handle(packet: Ipv4TcpPacket) {
        val key = Key(packet.sourceAddress, packet.sourcePort, packet.destinationAddress, packet.destinationPort)
        val syn = packet.flags and Ipv4TcpCodec.Flags.SYN != 0
        val ack = packet.flags and Ipv4TcpCodec.Flags.ACK != 0
        val rst = packet.flags and Ipv4TcpCodec.Flags.RST != 0
        val fin = packet.flags and Ipv4TcpCodec.Flags.FIN != 0

        reapIdle(key)

        if (rst) {
            connections.remove(key)?.let { close(it) }
            return
        }

        if (syn && !ack) {
            // A retransmitted SYN must not reset an existing connection's state; re-send SYN-ACK.
            connections[key]?.let { existing ->
                synchronized(existing) { existing.lastActivityMillis = nowMillis() }
                synchronized(existing) { sendSynAck(packet, existing) }
                return
            }
            if (connections.size >= maxConnections) {
                writePacket(Ipv4TcpCodec.reset(packet))
                return
            }
            val isn = nextIsn()
            val mss = effectiveMss(packet.mss)
            val connection = Connection(
                key = key,
                send = TcpSendQueue(isn = isn, mss = mss),
                isn = isn,
                clientIsn = packet.sequenceNumber,
                request = packet,
                lastActivityMillis = nowMillis(),
            )
            connection.stream.start(packet.sequenceNumber) // SYN consumes one sequence number
            connections[key] = connection
            sendSynAck(packet, connection)
            return
        }

        val connection = connections[key] ?: run {
            writePacket(Ipv4TcpCodec.reset(packet))
            return
        }
        synchronized(connection) {
            if (connection.closed) return@synchronized
            connection.request = packet
            connection.lastActivityMillis = nowMillis()

            // The third handshake packet must be a pure ACK of our ISN+1. Merely carrying ACK is not
            // enough: a stray ACK must not open the connection.
            if (!connection.established) {
                // Strict three-way handshake: the third packet must acknowledge our ISN+1 and carry
                // the client's next sequence number (client ISN+1). Anything else is reset.
                if (!ack || fin || packet.payload.isNotEmpty() ||
                    !serialEqual(packet.acknowledgmentNumber, (connection.isn + 1L) and SEQ_MASK) ||
                    !serialEqual(packet.sequenceNumber, (connection.clientIsn + 1L) and SEQ_MASK)
                ) {
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return@synchronized
                }
                connection.established = true
            } else if (ack) {
                // Once established, reject ACKs outside [SND.UNA, SND.NXT].
                if (!acknowledgmentAcceptable(connection, packet.acknowledgmentNumber)) {
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return@synchronized
                }
                val beforeUna = connection.send.sndUna
                connection.send.onAck(packet.acknowledgmentNumber)
                if (connection.send.sndUna != beforeUna) {
                    // Forward progress: reset duplicate-ACK state.
                    connection.lastAck = packet.acknowledgmentNumber
                    connection.dupAckCount = 0
                } else if (packet.payload.isEmpty() && !fin && connection.send.hasUnacked() &&
                    serialEqual(packet.acknowledgmentNumber, connection.lastAck)
                ) {
                    // Pure duplicate ACK with outstanding data: three in a row implies a lost
                    // segment (fast retransmit). Threshold avoids reacting to a single reordered ACK.
                    connection.dupAckCount++
                    if (connection.dupAckCount >= DUP_ACK_THRESHOLD) {
                        connection.dupAckCount = 0
                        retransmit(connection)
                    }
                }
            }

            if (fin) {
                // A FIN is only meaningful once the stream accepts it in order. An out-of-order or
                // duplicate FIN leaves inputClosed false; treating it as a real close would send our
                // FIN and drop the connection while the in-flight query is still unanswered.
                val accepted = connection.stream.accept(packet.sequenceNumber, packet.payload, fin = true)
                if (accepted != null && !consumeIntoFramer(connection, accepted)) {
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return@synchronized
                }
                if (connection.stream.inputClosed) connection.clientFin = true
            } else if (packet.payload.isNotEmpty()) {
                val accepted = connection.stream.accept(packet.sequenceNumber, packet.payload)
                if (accepted == null) {
                    // Duplicate or out-of-order/gap segment: ACK what we have and retransmit any
                    // unacknowledged answer (the client may be retrying a query whose reply was lost).
                    sendBareAck(packet, connection)
                    if (connection.send.hasUnacked()) retransmit(connection)
                    return@synchronized
                }
                if (!consumeIntoFramer(connection, accepted)) {
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return@synchronized
                }
            }

            // Send any pending answer segments that fit in the client's receive window.
            var emitted = 0
            connection.send.flush(packet.window) { seq, data ->
                writePacket(
                    Ipv4TcpCodec.build(
                        request = packet,
                        payload = data,
                        sequenceNumber = seq,
                        acknowledgmentNumber = connection.stream.expectedSequence,
                        flags = Ipv4TcpCodec.Flags.PSH or Ipv4TcpCodec.Flags.ACK,
                    ),
                )
                emitted++
            }

            // Acknowledge client data/FIN when no data segment carried the ACK.
            if ((fin || packet.payload.isNotEmpty()) && emitted == 0) {
                sendBareAck(packet, connection)
            }

            // Do NOT send FIN until every queued answer segment has been acknowledged.
            if (connection.clientFin && connection.send.allAcked() && !connection.ourFinSent) {
                connection.ourFinSent = true
                writePacket(
                    Ipv4TcpCodec.build(
                        request = packet,
                        payload = EMPTY,
                        sequenceNumber = connection.send.sndNxt,
                        acknowledgmentNumber = connection.stream.expectedSequence,
                        flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK,
                    ),
                )
                close(connection)
            }
        }
    }

    /** Feeds accepted bytes to the framer, frees the inbound buffer, queues one answer per message. */
    private fun consumeIntoFramer(connection: Connection, accepted: ByteArray): Boolean {
        val messages = connection.framer.feed(accepted)
        // Free inbound reassembly memory immediately: the framer owns its own bounded partial
        // buffer, so no TCP byte is lost and a long connection never accumulates processed data.
        connection.stream.drain()
        if (connection.framer.error) return false
        for (message in messages) {
            val response = resolve(message) ?: continue
            val framed = frameDnsTcp(response)
            if (!connection.send.queue(framed)) return false
        }
        return true
    }

    /** Drops all connections; called when the tunnel stops. */
    fun closeAll() {
        connections.values.toList().forEach { close(it) }
        connections.clear()
    }

    /** Removes half-open or abandoned flows; no polling, driven by packet arrival. */
    private fun reapIdle(activeKey: Key) {
        val now = nowMillis()
        if (now - lastReapMillis < REAP_INTERVAL_MILLIS) return
        lastReapMillis = now
        connections.values.forEach { flow ->
            if (flow.key != activeKey && now - flow.lastActivityMillis > idleTimeoutMillis) {
                close(flow)
                connections.remove(flow.key, flow)
            }
        }
    }

    private fun sendSynAck(packet: Ipv4TcpPacket, connection: Connection) {
        writePacket(
            Ipv4TcpCodec.build(
                request = packet,
                payload = EMPTY,
                sequenceNumber = connection.isn,
                acknowledgmentNumber = (packet.sequenceNumber + 1L) and SEQ_MASK,
                flags = Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK,
                // Advertise OUR receive MSS (MTU 1500 - headers). The client's advertised MSS is
                // stored in sendQueue and sizes OUR outbound segments, not this advertisement.
                options = Ipv4TcpCodec.mssOption(TcpSendQueue.MAX_MSS),
            ),
        )
    }

    private fun sendBareAck(packet: Ipv4TcpPacket, connection: Connection) {
        writePacket(
            Ipv4TcpCodec.build(
                request = packet,
                payload = EMPTY,
                sequenceNumber = connection.send.sndNxt,
                acknowledgmentNumber = connection.stream.expectedSequence,
                flags = Ipv4TcpCodec.Flags.ACK,
            ),
        )
    }

    private fun retransmit(connection: Connection) {
        connection.send.retransmit { seq, data ->
            writePacket(
                Ipv4TcpCodec.build(
                    request = connection.request,
                    payload = data,
                    sequenceNumber = seq,
                    acknowledgmentNumber = connection.stream.expectedSequence,
                    flags = Ipv4TcpCodec.Flags.PSH or Ipv4TcpCodec.Flags.ACK,
                ),
            )
        }
    }

    private fun acknowledgmentAcceptable(connection: Connection, ack: Long): Boolean {
        val a = ack and SEQ_MASK
        // SND.UNA <= ACK <= SND.NXT in serial arithmetic.
        return distance(connection.send.sndUna, a) >= 0L &&
            distance(a, connection.send.sndNxt) >= 0L
    }

    private fun close(connection: Connection) {
        if (connection.closed) return
        connection.closed = true
        connection.send.clear()
        // Centralized table cleanup: every close path (RST, FIN, malformed frame, bound exceeded,
        // idle reap) must remove the entry so it cannot leak or block new connections.
        connections.remove(connection.key, connection)
    }

    private fun effectiveMss(advertised: Int): Int =
        if (advertised in 1..TcpSendQueue.MAX_MSS) advertised else TcpSendQueue.MAX_MSS

    private fun serialEqual(a: Long, b: Long): Boolean = (a and SEQ_MASK) == (b and SEQ_MASK)

    /** Signed distance ([to] - [from]) in the 32-bit TCP sequence space; same convention as
     * TcpSendQueue.distance. */
    private fun distance(from: Long, to: Long): Long {
        val value = (to - from) and SEQ_MASK
        return if (value > 0x7FFFFFFFL) value - 0x1_0000_0000L else value
    }

    private companion object {
        const val MAX_CONNECTIONS: Int = 32
        const val REAP_INTERVAL_MILLIS: Long = 5_000L
        const val DUP_ACK_THRESHOLD: Int = 3
        const val SEQ_MASK: Long = 0xFFFFFFFFL
        val EMPTY = ByteArray(0)

        /** A clock-mixed ISN; a full TCP stack would add a secret PRF (RFC 9293 §3.4.1). */
        fun nextIsn(): Long = (System.currentTimeMillis() ushr 1) xor Random.nextLong(1L, Int.MAX_VALUE.toLong())
    }
}
