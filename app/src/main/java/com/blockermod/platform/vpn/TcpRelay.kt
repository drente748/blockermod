package com.blockermod.platform.vpn

import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import com.blockermod.core.net.TcpStreamBuffer
import com.blockermod.core.policy.TransportPolicy
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * Userspace TCP relay for the experimental full-tunnel mode.
 *
 * This is not a full TCP stack (RFC 9293): it does not retransmit injected segments, manage a
 * congestion window or implement TIME-WAIT. It DOES provide the properties needed to filter DNS
 * safely: per-flow FIFO handling, sequence-aware inbound reassembly with duplicate detection,
 * bounded memory, SYN/ACK/FIN/RST lifecycle, idle cleanup and deferred socket creation after policy
 * checks. General TCP is best-effort and this limitation is documented.
 */
internal class TcpRelay(
    private val protectSocket: (Socket) -> Boolean,
    private val writePacket: (ByteArray) -> Unit,
    private val transportPolicy: TransportPolicy,
    private val onDohBlocked: () -> Unit,
    private val connectTimeoutMillis: Int = 5_000,
    private val idleTimeoutMillis: Long = 60_000L,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
) {

    private data class Key(
        val sourceAddress: Int,
        val sourcePort: Int,
        val destinationAddress: Int,
        val destinationPort: Int,
    )

    private inner class Connection(
        val key: Key,
        val ourIsn: Long,
        var request: Ipv4TcpPacket,
    ) {
        val stream = TcpStreamBuffer()
        var lastActivityMillis: Long = nowMillis()
        var socket: Socket? = null
        var serverBytes: Long = 0L
        var tlsDecision: TlsInspection = TlsInspection.UNKNOWN
        var tlsName: String? = null
        var policyDecided: Boolean = false
        var closed: Boolean = false
        val lock = Any()

        fun nextServerSeq(): Long = (ourIsn + 1L + serverBytes) and 0xFFFFFFFFL
    }

    private val connections = ConcurrentHashMap<Key, Connection>()
    private var lastReapMillis: Long = 0L

    fun connectionCount(): Int = connections.size

    /** Handles one inbound TCP packet. Called serially per flow by VpnTunnel. */
    fun handle(packet: Ipv4TcpPacket) {
        val key = Key(packet.sourceAddress, packet.sourcePort, packet.destinationAddress, packet.destinationPort)
        val syn = packet.flags and Ipv4TcpCodec.Flags.SYN != 0
        val ack = packet.flags and Ipv4TcpCodec.Flags.ACK != 0
        val rst = packet.flags and Ipv4TcpCodec.Flags.RST != 0
        val fin = packet.flags and Ipv4TcpCodec.Flags.FIN != 0

        // Defensive port-853 gate (A3): DoT is encrypted DNS for every destination. VpnTunnel
        // decides first; this check keeps the relay safe if it is ever reused directly.
        if (packet.destinationPort == DOT_PORT) {
            val action = transportPolicy.decide(
                com.blockermod.core.policy.PacketTransport.TCP_DOT_853,
                key.destinationAddress.ipv4String(),
            )
            if (action == com.blockermod.core.policy.TransportAction.BLOCK_ENCRYPTED_DNS) {
                onDohBlocked()
                writePacket(Ipv4TcpCodec.reset(packet))
                return
            }
        }

        // Reap BEFORE taking any connection lock. reapIdle() locks other flows via close(); calling
        // it while holding one flow's lock would allow two workers to deadlock (A holds lock A and
        // wants B, while B holds lock B and wants A). No thread holds a flow lock while reaping.
        // Skip this packet's own flow: a packet just arrived for it, so it is clearly not idle.
        reapIdle(key)

        if (rst) {
            close(connections.remove(key))
            return
        }

        if (syn && !ack) {
            // A retransmitted SYN (our SYN-ACK was lost) must re-send SYN-ACK — a bare ACK cannot
            // complete the client's handshake. It must not reset a live connection either.
            connections[key]?.let { existing ->
                synchronized(existing.lock) { sendSynAck(packet, existing) }
                return
            }
            if (connections.size >= MAX_CONNECTIONS) {
                writePacket(Ipv4TcpCodec.reset(packet))
                return
            }
            val connection = Connection(key, nextIsn(), packet)
            connections[key] = connection
            synchronized(connection.lock) {
                connection.stream.start(packet.sequenceNumber)
                sendSynAck(packet, connection)
            }
            return
        }

        val connection = connections[key] ?: run {
            writePacket(Ipv4TcpCodec.reset(packet))
            return
        }
        synchronized(connection.lock) {
            if (connection.closed) return@synchronized
            connection.request = packet
            connection.lastActivityMillis = nowMillis()

            val accepted = connection.stream.accept(packet.sequenceNumber, packet.payload, fin)
            // accepted == null means either a duplicate/gap OR a pure ACK/FIN (no payload). Only a
            // gap/duplicate needs a bare ACK; a pure ACK does not (no ACK-on-ACK), and a FIN whose
            // sequence was not in order must NOT close the flow or buffered data would be lost.
            if (accepted == null && !connection.stream.inputClosed) {
                if (!packet.payload.isEmpty() || fin) sendAck(packet, connection)
                return@synchronized
            }
            if (accepted != null && !connection.policyDecided) {
                // Inspect the WHOLE accumulated stream, not just this segment: a ClientHello split
                // across segments must still be recognized as SNI / ECH.
                inspectClientData(connection, packet, connection.stream.buffered())
                if (connection.closed) return@synchronized
            }

            if (connection.policyDecided && connection.stream.bufferedSize() > 0) {
                // Flush every held byte once the policy allows the flow; otherwise the first
                // segment of a split ClientHello would be dropped and corrupt the upstream request.
                val pending = connection.stream.drain()
                if (connection.socket == null && !connect(connection)) {
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return@synchronized
                }
                try {
                    val out = connection.socket?.getOutputStream() ?: return@synchronized
                    out.write(pending)
                    out.flush()
                } catch (exception: Exception) {
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return@synchronized
                }
            }
            if (connection.stream.inputClosed) {
                // A single FIN/ACK, at the current SND.NXT, after all accepted data was flushed.
                writePacket(
                    Ipv4TcpCodec.build(
                        request = packet,
                        payload = EMPTY,
                        sequenceNumber = connection.nextServerSeq(),
                        acknowledgmentNumber = connection.stream.expectedSequence,
                        flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK,
                    ),
                )
                close(connection)
            }
        }
    }

    /** Applies the encrypted-DNS transport policy to the reassembled client stream (A3). */
    private fun inspectClientData(connection: Connection, packet: Ipv4TcpPacket, bytes: ByteArray) {
        if (packet.destinationPort == 443 && !connection.policyDecided) {
            val result = TlsSniInspector.inspect(bytes)
            connection.tlsDecision = result.kind
            connection.tlsName = result.serverName
            when (result.kind) {
                TlsInspection.MALFORMED -> {
                    // Malformed TLS on 443 is not necessarily DoH; let it through but stop inspecting.
                    connection.policyDecided = true
                }
                TlsInspection.SNI, TlsInspection.ECH -> {
                    // The transport policy is the single decision point for TCP/443: it blocks a
                    // known DoH SNI and allows ECH (documented blind spot). The relay no longer
                    // applies a parallel matcher of its own.
                    val action = transportPolicy.decide(
                        com.blockermod.core.policy.PacketTransport.TCP_DOH_443,
                        connection.key.destinationAddress.ipv4String(),
                        serverName = result.serverName,
                        echDetected = result.kind == TlsInspection.ECH,
                    )
                    connection.policyDecided = true
                    if (action == com.blockermod.core.policy.TransportAction.BLOCK_ENCRYPTED_DNS) {
                        onDohBlocked()
                        writePacket(Ipv4TcpCodec.reset(packet))
                        close(connection)
                    }
                }
                TlsInspection.UNKNOWN -> {
                    // Need more bytes to decide; keep the socket closed until the decision exists.
                    if (bytes.size >= MAX_TLS_PREFILTER) {
                        connection.policyDecided = true
                    }
                }
            }
        } else {
            connection.policyDecided = true
        }
    }

    private fun sendSynAck(packet: Ipv4TcpPacket, connection: Connection) {
        writePacket(
            Ipv4TcpCodec.build(
                request = packet,
                payload = EMPTY,
                sequenceNumber = connection.ourIsn,
                acknowledgmentNumber = connection.stream.expectedSequence,
                flags = Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK,
                options = Ipv4TcpCodec.mssOption(MSS),
            ),
        )
    }

    private fun sendAck(packet: Ipv4TcpPacket, connection: Connection) {
        writePacket(
            Ipv4TcpCodec.build(
                request = packet,
                payload = EMPTY,
                sequenceNumber = connection.nextServerSeq(),
                acknowledgmentNumber = connection.stream.expectedSequence,
                flags = Ipv4TcpCodec.Flags.ACK,
            ),
        )
    }

    /** Closes idle flows without polling or sleeping: called from packet handling only. */
    private fun reapIdle(activeKey: Key) {
        val now = nowMillis()
        // Scanning the whole table on every packet is wasteful under load. A time gate keeps the
        // cleanup bound cheap; idle flows are still reaped within (gate + idle timeout). No timer,
        // sleep or scheduler is involved — reaping is driven by packet arrival.
        if (now - lastReapMillis < REAP_INTERVAL_MILLIS) return
        lastReapMillis = now
        connections.values.forEach { flow ->
            // Never reap the flow that just sent a packet, even if its stored timestamp is old.
            if (flow.key != activeKey && now - flow.lastActivityMillis > idleTimeoutMillis) {
                close(flow)
                connections.remove(flow.key, flow)
            }
        }
    }

    private fun connect(connection: Connection): Boolean {
        val key = connection.key
        var candidate: Socket? = null
        try {
            candidate = Socket()
            if (!protectSocket(candidate)) throw SocketException("socket could not be protected")
            val address = InetAddress.getByAddress(
                byteArrayOf(
                    (key.destinationAddress ushr 24).toByte(),
                    (key.destinationAddress ushr 16).toByte(),
                    (key.destinationAddress ushr 8).toByte(),
                    key.destinationAddress.toByte(),
                ),
            )
            // No read soTimeout: a blocked read is interrupted by close() on idle reap / stop.
            // A 5s read timeout would tear down every idle connection and cause socket churn.
            candidate.connect(InetSocketAddress(address, key.destinationPort), connectTimeoutMillis)
            candidate.tcpNoDelay = true
        } catch (exception: Exception) {
            // A failed protect/connect still allocates an fd; close it before failing closed.
            try { candidate?.close() } catch (ignored: Exception) {}
            return false
        }
        connection.socket = candidate
        Thread({ pumpFromServer(connection) }, "blockermod-tcp-relay").apply { isDaemon = true }.start()
        return true
    }

    private fun pumpFromServer(connection: Connection) {
        val buffer = ByteArray(SEGMENT_SIZE)
        try {
            while (!connection.closed) {
                val socket = connection.socket ?: break
                val count = socket.getInputStream().read(buffer)
                if (count < 0) break
                if (count == 0) continue
                val segment = buffer.copyOf(count)
                synchronized(connection.lock) {
                    writePacket(
                        Ipv4TcpCodec.build(
                            request = connection.request,
                            payload = segment,
                            sequenceNumber = connection.nextServerSeq(),
                            acknowledgmentNumber = connection.stream.expectedSequence,
                            flags = Ipv4TcpCodec.Flags.PSH or Ipv4TcpCodec.Flags.ACK,
                        ),
                    )
                    connection.serverBytes = (connection.serverBytes + count.toLong()) and 0xFFFFFFFFL
                    connection.lastActivityMillis = nowMillis()
                }
            }
            synchronized(connection.lock) {
                if (!connection.closed) {
                    writePacket(
                        Ipv4TcpCodec.build(
                            request = connection.request,
                            payload = EMPTY,
                            sequenceNumber = connection.nextServerSeq(),
                            acknowledgmentNumber = connection.stream.expectedSequence,
                            flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK,
                        ),
                    )
                }
            }
        } catch (exception: Exception) {
            // Connection ended (peer close, timeout or stop); cleanup happens in finally.
        } finally {
            close(connection)
            connections.remove(connection.key, connection)
        }
    }

    fun closeAll() {
        connections.values.toList().forEach { close(it) }
        connections.clear()
    }

    private fun close(connection: Connection?) {
        if (connection == null) return
        synchronized(connection.lock) {
            if (connection.closed) return
            connection.closed = true
        }
        // Centralize table cleanup: FIN, RST, connect failure and idle reaping all funnel here, so
        // a closed flow can never remain counted against MAX_CONNECTIONS.
        connections.remove(connection.key, connection)
        try {
            connection.socket?.close()
        } catch (ignored: Exception) {
            // already closed
        }
    }

    private companion object {
        const val MAX_CONNECTIONS: Int = 128
        const val REAP_INTERVAL_MILLIS: Long = 5_000L
        const val MSS: Int = 1460
        const val SEGMENT_SIZE: Int = 1460
        const val MAX_TLS_PREFILTER: Int = 16 * 1024
        const val DOT_PORT: Int = 853
        val EMPTY = ByteArray(0)

        fun nextIsn(): Long = (System.currentTimeMillis() ushr 1) xor Random.nextLong(1L, Int.MAX_VALUE.toLong())
    }
}

/** Formats a raw IPv4 address (network byte order int) as a dotted quad. */
internal fun Int.ipv4String(): String =
    "${(this ushr 24) and 0xFF}.${(this ushr 16) and 0xFF}.${(this ushr 8) and 0xFF}.${this and 0xFF}"
