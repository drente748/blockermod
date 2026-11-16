package com.blockermod.platform.vpn

import android.util.Log
import com.blockermod.core.DomainMatcher
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * Small userspace TCP relay for the full-tunnel engine.
 *
 * The local SYN/SYN-ACK handshake is answered immediately without touching the network. The real
 * socket is created lazily, on the first payload, after the DoH/SNI and DNS-over-TCP checks have
 * passed. That way a blocked encrypted-DNS connection never reaches the network at all.
 *
 * For allowed traffic the payload is relayed through a [Socket] protected from the VPN, and server
 * bytes are injected back into the tunnel as TCP segments.
 */
internal class TcpRelay(
    private val protectSocket: (Socket) -> Boolean,
    private val writePacket: (ByteArray) -> Unit,
    private val dohHosts: DomainMatcher,
    private val onDohBlocked: () -> Unit,
    private val dnsPolicy: (ByteArray) -> ByteArray?,
    private val connectTimeoutMillis: Int = 5_000,
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
        var clientNextSeq: Long,
        var request: Ipv4TcpPacket,
    ) {
        var socket: Socket? = null
        var totalWrittenFromServer: Long = 0L
        var closed: Boolean = false
        val lock = Any()

        fun nextServerSeq(): Long = ourIsn + 1L + totalWrittenFromServer
    }

    private val connections = ConcurrentHashMap<Key, Connection>()

    /** Handles one inbound TCP packet. Called from the tunnel worker pool. */
    fun handle(packet: Ipv4TcpPacket) {
        val key = Key(packet.sourceAddress, packet.sourcePort, packet.destinationAddress, packet.destinationPort)
        val isSyn = packet.flags and Ipv4TcpCodec.Flags.SYN != 0
        val isAck = packet.flags and Ipv4TcpCodec.Flags.ACK != 0
        val isRst = packet.flags and Ipv4TcpCodec.Flags.RST != 0
        val isFin = packet.flags and Ipv4TcpCodec.Flags.FIN != 0

        if (isSyn && !isAck) {
            // Each connection owns a socket and a relay thread; cap them to protect the device.
            if (!connections.containsKey(key) && connections.size >= MAX_CONNECTIONS) {
                writePacket(Ipv4TcpCodec.reset(packet))
                return
            }
            open(key, packet)
            return
        }

        val connection = connections[key] ?: run {
            writePacket(Ipv4TcpCodec.reset(packet))
            return
        }

        if (isRst) {
            close(connection)
            return
        }

        synchronized(connection.lock) {
            connection.request = packet
            connection.clientNextSeq = packet.sequenceNumber + packet.payload.size.toLong() +
                (if (isSyn) 1L else 0L) + (if (isFin) 1L else 0L)

            if (isFin) {
                writePacket(
                    Ipv4TcpCodec.build(
                        request = packet,
                        payload = EMPTY,
                        sequenceNumber = connection.nextServerSeq(),
                        acknowledgmentNumber = connection.clientNextSeq,
                        flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK,
                    ),
                )
                close(connection)
                return
            }
            if (packet.payload.isEmpty()) return // pure ACK

            // TLS ClientHello: block DoH endpoints before a socket is created.
            if (TlsSniInspector.isClientHello(packet.payload)) {
                val sni = TlsSniInspector.extract(packet.payload)
                if (sni != null && dohHosts.matches(sni)) {
                    onDohBlocked()
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return
                }
            }

            // DNS over TCP is answered entirely by the local resolver — no socket is created.
            if (packet.destinationPort == 53) {
                val response = dnsPolicy(packet.payload)
                if (response != null) {
                    writePacket(
                        Ipv4TcpCodec.build(
                            request = packet,
                            payload = response,
                            sequenceNumber = connection.nextServerSeq(),
                            acknowledgmentNumber = connection.clientNextSeq,
                            flags = Ipv4TcpCodec.Flags.PSH or Ipv4TcpCodec.Flags.ACK,
                        ),
                    )
                    connection.totalWrittenFromServer += response.size
                    return
                }
                writePacket(Ipv4TcpCodec.reset(packet))
                close(connection)
                return
            }

            if (connection.socket == null) {
                if (!connect(connection)) {
                    writePacket(Ipv4TcpCodec.reset(packet))
                    close(connection)
                    return
                }
            }

            try {
                val socket = connection.socket ?: error("socket not connected")
                socket.getOutputStream().write(packet.payload)
                socket.getOutputStream().flush()
            } catch (exception: Exception) {
                writePacket(Ipv4TcpCodec.reset(packet))
                close(connection)
                return
            }

            writePacket(
                Ipv4TcpCodec.build(
                    request = packet,
                    payload = EMPTY,
                    sequenceNumber = connection.nextServerSeq(),
                    acknowledgmentNumber = connection.clientNextSeq,
                    flags = Ipv4TcpCodec.Flags.ACK,
                ),
            )
        }
    }

    /** Closes every connection; called when the tunnel stops. */
    fun closeAll() {
        connections.values.toList().forEach { close(it) }
        connections.clear()
    }

    /** Answers a local SYN without touching the network. */
    private fun open(key: Key, packet: Ipv4TcpPacket) {
        // A repeated SYN (retransmission) replaces the previous half-open connection.
        connections[key]?.let { close(it) }
        val connection = Connection(
            key = key,
            ourIsn = Random.nextLong(1L, Int.MAX_VALUE.toLong()),
            clientNextSeq = packet.sequenceNumber + 1L,
            request = packet,
        )
        connections[key] = connection

        writePacket(
            Ipv4TcpCodec.build(
                request = packet,
                payload = EMPTY,
                sequenceNumber = connection.ourIsn,
                acknowledgmentNumber = connection.clientNextSeq,
                flags = Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK,
                options = Ipv4TcpCodec.mssOption(MSS),
            ),
        )
    }

    /** Creates the protected socket only after the payload has passed the policy checks. */
    private fun connect(connection: Connection): Boolean {
        val key = connection.key
        val socket = try {
            Socket().also { candidate ->
                if (!protectSocket(candidate)) throw SocketException("socket could not be protected")
                val address = InetAddress.getByAddress(
                    byteArrayOf(
                        (key.destinationAddress ushr 24).toByte(),
                        (key.destinationAddress ushr 16).toByte(),
                        (key.destinationAddress ushr 8).toByte(),
                        key.destinationAddress.toByte(),
                    ),
                )
                candidate.connect(InetSocketAddress(address, key.destinationPort), connectTimeoutMillis)
                candidate.tcpNoDelay = true
            }
        } catch (exception: Exception) {
            Log.w(TAG, "could not open TCP relay to ${key.destinationPort}", exception)
            return false
        }
        connection.socket = socket
        Thread({ pumpFromServer(connection) }, "blockermod-tcp-relay").apply { isDaemon = true }.start()
        return true
    }

    /** Reads server bytes and injects them back into the tunnel as TCP segments. */
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
                            acknowledgmentNumber = connection.clientNextSeq,
                            flags = Ipv4TcpCodec.Flags.PSH or Ipv4TcpCodec.Flags.ACK,
                        ),
                    )
                    connection.totalWrittenFromServer += count.toLong()
                }
            }
            synchronized(connection.lock) {
                if (!connection.closed) {
                    writePacket(
                        Ipv4TcpCodec.build(
                            request = connection.request,
                            payload = EMPTY,
                            sequenceNumber = connection.nextServerSeq(),
                            acknowledgmentNumber = connection.clientNextSeq,
                            flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK,
                        ),
                    )
                }
            }
        } catch (exception: Exception) {
            if (!connection.closed) Log.d(TAG, "TCP relay ended: ${exception.javaClass.simpleName}")
        } finally {
            close(connection)
        }
    }

    private fun close(connection: Connection) {
        synchronized(connection.lock) {
            if (connection.closed) return
            connection.closed = true
        }
        connections.remove(connection.key, connection)
        try {
            connection.socket?.close()
        } catch (ignored: Exception) {
            // already closed
        }
    }

    private companion object {
        const val TAG = "BlockerMod"
        const val MAX_CONNECTIONS: Int = 128
        const val MSS: Int = 1460
        const val SEGMENT_SIZE: Int = 1460
        val EMPTY = ByteArray(0)
    }
}
