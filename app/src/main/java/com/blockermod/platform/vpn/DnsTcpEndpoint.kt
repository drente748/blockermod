package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsTcpFramer
import com.blockermod.core.dns.frameDnsTcp
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import com.blockermod.core.net.TcpStreamBuffer
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * DNS-only mode's TCP/53 endpoint.
 *
 * This is deliberately NOT a general TCP stack: it accepts a local client's TCP connection to the
 * virtual DNS address, reassembles the inbound byte stream, parses DNS-over-TCP frames, answers each
 * frame with the same [LocalDnsResolver] used by UDP, then closes the connection. General TCP is not
 * accepted in DNS-only mode (no default route captures it).
 *
 * Connections are keyed by the 4-tuple and bounded; each connection owns a bounded reassembly
 * buffer. There is no thread per connection: all work happens on the caller's thread.
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
        val isn: Long = nextIsn(),
        var sndNxt: Long = isn + 1L,
        var closed: Boolean = false,
        var request: Ipv4TcpPacket? = null,
        var lastActivityMillis: Long,
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
            connections.remove(key)
            return
        }

        if (syn && !ack) {
            // A retransmitted SYN must not reset an existing connection's reassembly state; just
            // re-send the SYN-ACK so the client can complete the handshake.
            connections[key]?.let { existing ->
                synchronized(existing) { existing.lastActivityMillis = nowMillis() }
                sendSynAck(packet, existing)
                return
            }
            if (connections.size >= maxConnections) {
                writePacket(Ipv4TcpCodec.reset(packet))
                return
            }
            val connection = Connection(key = key, lastActivityMillis = nowMillis()).also { it.request = packet }
            // The SYN consumes one sequence number; data starts at seq+1. Without this the data
            // path sees an unstarted stream and answers every segment with RST.
            connection.stream.start(packet.sequenceNumber)
            connections[key] = connection
            sendSynAck(packet, connection)
            return
        }

        val connection = connections[key] ?: run {
            writePacket(Ipv4TcpCodec.reset(packet))
            return
        }
        synchronized(connection) {
            connection.request = packet
            connection.lastActivityMillis = nowMillis()
            if (!ack || !connection.stream.started) {
                writePacket(Ipv4TcpCodec.reset(packet))
                connections.remove(key, connection)
                return
            }

            if (fin) {
                val bytes = connection.stream.accept(packet.sequenceNumber, packet.payload, fin = true)
                if (bytes != null && !connection.framer.error) {
                    answerFrames(packet, connection, connection.framer.feed(bytes))
                }
                send(packet, connection, EMPTY, Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK)
                connections.remove(key, connection)
                return
            }

            val bytes = connection.stream.accept(packet.sequenceNumber, packet.payload) ?: run {
                // Duplicate or gap: acknowledge what we have so the peer can retransmit.
                send(packet, connection, EMPTY, Ipv4TcpCodec.Flags.ACK)
                return
            }
            val messages = connection.framer.feed(bytes)
            if (connection.framer.error) {
                writePacket(Ipv4TcpCodec.reset(packet))
                connections.remove(key, connection)
                return
            }
            answerFrames(packet, connection, messages)
        }
    }

    /** Drops all connections; called when the tunnel stops. */
    fun closeAll() = connections.clear()

    /** Removes half-open or abandoned flows; no polling, driven by packet arrival. */
    private fun reapIdle(activeKey: Key) {
        val now = nowMillis()
        // Gate the O(n) scan so a busy stream of DNS packets does not rescan the table each time.
        if (now - lastReapMillis < REAP_INTERVAL_MILLIS) return
        lastReapMillis = now
        connections.values.forEach { flow ->
            // A packet just arrived for this flow; it cannot be idle.
            if (flow.key != activeKey && now - flow.lastActivityMillis > idleTimeoutMillis) {
                connections.remove(flow.key, flow)
            }
        }
    }

    private fun answerFrames(
        packet: Ipv4TcpPacket,
        connection: Connection,
        messages: List<ByteArray>,
    ) {
        for (message in messages) {
            val response = resolve(message) ?: continue
            send(packet, connection, frameDnsTcp(response), Ipv4TcpCodec.Flags.PSH or Ipv4TcpCodec.Flags.ACK)
        }
    }

    private fun sendSynAck(packet: Ipv4TcpPacket, connection: Connection) {
        writePacket(
            Ipv4TcpCodec.build(
                request = packet,
                payload = EMPTY,
                sequenceNumber = connection.isn,
                acknowledgmentNumber = (packet.sequenceNumber + 1L) and 0xFFFFFFFFL,
                flags = Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK,
                options = Ipv4TcpCodec.mssOption(MSS),
            ),
        )
    }

    private fun send(
        packet: Ipv4TcpPacket,
        connection: Connection,
        payload: ByteArray,
        flags: Int,
    ) {
        writePacket(
            Ipv4TcpCodec.build(
                request = packet,
                payload = payload,
                sequenceNumber = connection.sndNxt,
                acknowledgmentNumber = connection.stream.expectedSequence,
                flags = flags,
            ),
        )
        connection.sndNxt = (connection.sndNxt + payload.size.toLong()) and 0xFFFFFFFFL
    }

    private companion object {
        const val MAX_CONNECTIONS: Int = 32
        const val REAP_INTERVAL_MILLIS: Long = 5_000L
        const val MSS: Int = 1460
        val EMPTY = ByteArray(0)

        /** A clock-mixed ISN; a full TCP stack would add a secret PRF (RFC 9293 §3.4.1). */
        fun nextIsn(): Long = (System.currentTimeMillis() ushr 1) xor Random.nextLong(1L, Int.MAX_VALUE.toLong())
    }
}
