package com.blockermod.platform.vpn

import com.blockermod.core.net.Ipv4UdpCodec
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * UDP relay for the full-tunnel engine: forwards allowed UDP flows through protected sockets and
 * injects the replies back into the tunnel.
 *
 * Flow creation is atomic (ConcurrentHashMap.compute): two tunnel workers receiving the first two
 * datagrams of one flow can never open two sockets or two pump threads. Idle flows are reaped from
 * packet arrival with a time-gated scan; there is no timer, sleep or polling. IPv4 fragments are not
 * reassembled here (known limit): a fragmented datagram is handled as received by the codec.
 */
internal open class UdpRelay(
    private val protectSocket: (DatagramSocket) -> Boolean,
    private val writePacket: (ByteArray) -> Unit,
    private val idleTimeoutMillis: Long = DEFAULT_IDLE_TIMEOUT_MILLIS,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
) {

    private data class Key(
        val sourceAddress: Int,
        val sourcePort: Int,
        val destinationAddress: Int,
        val destinationPort: Int,
    )

    private inner class Flow(val key: Key, val socket: DatagramSocket) {
        val closed = AtomicBoolean(false)
        @Volatile
        var lastActivityMillis: Long = nowMillis()
    }

    private val flows = ConcurrentHashMap<Key, Flow>()
    private val liveCount = AtomicInteger(0)
    @Volatile
    private var lastReapMillis: Long = 0L

    /** Number of live UDP flows, exposed for tests and resource monitoring. */
    fun flowCount(): Int = flows.size

    /** Forwards one UDP datagram. Called from the tunnel worker pool. */
    open fun handle(packet: com.blockermod.core.net.Ipv4UdpPacket) {
        val key = Key(packet.sourceAddress, packet.sourcePort, packet.destinationAddress, packet.destinationPort)
        reapIdle(key)

        // compute() runs the mapping function once per key: exactly one caller creates the socket.
        // The loser receives the existing flow and never opens a second one (C1).
        var created: Flow? = null
        val flow = flows.compute(key) { _, existing ->
            if (existing != null) {
                existing
            } else if (liveCount.get() >= MAX_FLOWS) {
                null
            } else {
                val opened = open(key)
                if (opened != null) liveCount.incrementAndGet()
                created = opened
                opened
            }
        } ?: return
        if (created != null) {
            Thread({ pump(flow) }, "blockermod-udp-relay").apply { isDaemon = true }.start()
        }
        flow.lastActivityMillis = nowMillis()

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

    /** Creates the socket but does NOT insert it or start a thread; compute() owns both. */
    private fun open(key: Key): Flow? {
        val socket = try {
            DatagramSocket().also { candidate ->
                if (!protectSocket(candidate)) throw Exception("socket could not be protected")
                // No soTimeout: a 30s read timeout tore down healthy idle QUIC/NAT flows and caused
                // socket churn. Idle reaping is packet-driven below.
            }
        } catch (exception: Exception) {
            return null
        }
        return Flow(key, socket)
    }

    private fun pump(flow: Flow) {
        val buffer = ByteArray(MAX_DATAGRAM)
        while (!flow.closed.get()) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                flow.socket.receive(packet) // blocking; close() interrupts it on stop/reap
                flow.lastActivityMillis = nowMillis()
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

    /** Reclaims idle flows on packet arrival only: no timer, sleep or polling (battery contract). */
    private fun reapIdle(activeKey: Key) {
        val now = nowMillis()
        if (now - lastReapMillis < REAP_INTERVAL_MILLIS) return
        lastReapMillis = now
        flows.values.forEach { flow ->
            if (flow.key != activeKey && now - flow.lastActivityMillis > idleTimeoutMillis) {
                close(flow.key)
            }
        }
    }

    /** Closes every flow; called when the tunnel stops. */
    fun closeAll() {
        flows.keys.toList().forEach { close(it) }
        flows.clear()
    }

    private fun close(key: Key) {
        val flow = flows.remove(key) ?: return
        if (flow.closed.compareAndSet(false, true)) {
            liveCount.decrementAndGet()
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
        const val DEFAULT_IDLE_TIMEOUT_MILLIS: Long = 120_000L
        const val REAP_INTERVAL_MILLIS: Long = 5_000L
        val EMPTY = ByteArray(0)
    }
}
