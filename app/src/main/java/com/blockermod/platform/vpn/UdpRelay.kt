package com.blockermod.platform.vpn

import com.blockermod.core.net.Ipv4UdpCodec
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * UDP relay for the full-tunnel engine: forwards allowed UDP flows through protected sockets and
 * injects the replies back into the tunnel.
 */
internal class UdpRelay(
    private val protectSocket: (DatagramSocket) -> Boolean,
    private val writePacket: (ByteArray) -> Unit,
    private val timeoutMillis: Int = 30_000,
) {

    private data class Key(
        val sourceAddress: Int,
        val sourcePort: Int,
        val destinationAddress: Int,
        val destinationPort: Int,
    )

    private inner class Flow(val key: Key, val socket: DatagramSocket) {
        val closed = AtomicBoolean(false)
    }

    private val flows = ConcurrentHashMap<Key, Flow>()

    /** Forwards one UDP datagram. Called from the tunnel worker pool. */
    fun handle(packet: com.blockermod.core.net.Ipv4UdpPacket) {
        val key = Key(packet.sourceAddress, packet.sourcePort, packet.destinationAddress, packet.destinationPort)
        // Each flow owns a socket and a blocking-read thread; cap them to protect the device.
        if (!flows.containsKey(key) && flows.size >= MAX_FLOWS) return
        val flow = flows.getOrPut(key) { open(key) ?: return }

        val address = InetAddress.getByAddress(
            byteArrayOf(
                (key.destinationAddress ushr 24).toByte(),
                (key.destinationAddress ushr 16).toByte(),
                (key.destinationAddress ushr 8).toByte(),
                key.destinationAddress.toByte(),
            ),
        )
        try {
            flow.socket.send(DatagramPacket(packet.payload, packet.payload.size, address, key.destinationPort))
        } catch (exception: Exception) {
            close(key)
        }
    }

    private fun open(key: Key): Flow? {
        val socket = try {
            DatagramSocket().also { candidate ->
                if (!protectSocket(candidate)) throw Exception("socket could not be protected")
                candidate.soTimeout = timeoutMillis
            }
        } catch (exception: Exception) {
            return null
        }
        val flow = Flow(key, socket)
        flows[key] = flow
        Thread({ pump(flow) }, "blockermod-udp-relay").apply { isDaemon = true }.start()
        return flow
    }

    private fun pump(flow: Flow) {
        val buffer = ByteArray(MAX_DATAGRAM)
        while (!flow.closed.get()) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                flow.socket.receive(packet)
                val reply = Ipv4UdpCodec.buildIpv4UdpResponse(
                    com.blockermod.core.net.Ipv4UdpPacket(
                        sourceAddress = flow.key.sourceAddress,
                        destinationAddress = flow.key.destinationAddress,
                        sourcePort = flow.key.sourcePort,
                        destinationPort = flow.key.destinationPort,
                        payload = EMPTY,
                        identification = 0,
                        ttl = 64,
                        ipHeaderLength = 20,
                    ),
                    packet.data.copyOf(packet.length),
                )
                writePacket(reply)
            } catch (exception: Exception) {
                break
            }
        }
        close(flow.key)
    }

    /** Closes every flow; called when the tunnel stops. */
    fun closeAll() {
        flows.keys.toList().forEach { close(it) }
        flows.clear()
    }

    private fun close(key: Key) {
        val flow = flows.remove(key) ?: return
        if (flow.closed.compareAndSet(false, true)) {
            try {
                flow.socket.close()
            } catch (ignored: Exception) {
                // already closed
            }
        }
    }

    private companion object {
        const val MAX_DATAGRAM: Int = 4096
        const val MAX_FLOWS: Int = 128
        val EMPTY = ByteArray(0)
    }
}
