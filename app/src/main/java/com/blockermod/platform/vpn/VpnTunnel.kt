package com.blockermod.platform.vpn

import com.blockermod.core.DomainMatcher
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4UdpCodec
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Lifecycle state of the tunnel.
 */
internal enum class TunnelState {
    /** The tunnel is not running. */
    Idle,

    /** The tunnel is reading packets and answering them. */
    Running,
}

/**
 * The DNS tunnel: one reader thread, a bounded worker pool, and a waiter thread that sleeps on a
 * latch instead of polling.
 *
 * The tunnel is deliberately free of Android types so that its lifecycle can be tested on a plain
 * JVM: the service hands it the streams of the tunnel file descriptor.
 */
internal class VpnTunnel(
    private val input: InputStream,
    private val output: OutputStream,
    private val responder: DnsResponder,
    private val workerCount: Int = WORKER_COUNT,
    private val pendingLimit: Int = PENDING_LIMIT,
    private val fullTunnel: Boolean = false,
    private val tcpRelay: TcpRelay? = null,
    private val udpRelay: UdpRelay? = null,
) {

    /** Current lifecycle state of the tunnel. */
    @Volatile
    var state: TunnelState = TunnelState.Idle
        private set

    private val shutdownLatch = CountDownLatch(1)
    private val outputLock = Any()
    private val droppedPackets = AtomicLong()
    private val tcpPackets = AtomicLong()
    private val answeredPackets = AtomicLong()

    private val executor = ThreadPoolExecutor(
        workerCount,
        workerCount,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(pendingLimit),
        { runnable -> Thread(runnable, WORKER_THREAD_NAME).apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    private val readerThread = Thread({ readLoop() }, READER_THREAD_NAME).apply { isDaemon = true }
    private val waiterThread = Thread({ awaitShutdown() }, WAITER_THREAD_NAME).apply { isDaemon = true }

    /**
     * Starts the reader and the waiter threads.
     */
    fun start() {
        if (state != TunnelState.Idle) return
        state = TunnelState.Running
        readerThread.start()
        waiterThread.start()
    }

    /**
     * Signals the tunnel to stop.
     *
     * The waiter thread wakes up on the latch, closes the tunnel stream to wake the blocked reader,
     * and drains the worker pool. No polling and no sleeping is involved.
     */
    fun stop() {
        if (state == TunnelState.Idle) return
        shutdownLatch.countDown()
    }

    /**
     * Waits until the tunnel stopped and the reader thread finished.
     *
     * @return true when the tunnel is idle again.
     */
    fun awaitStopped(timeoutMillis: Long): Boolean {
        val signalled = shutdownLatch.await(timeoutMillis, TimeUnit.MILLISECONDS)
        readerThread.join(timeoutMillis)
        waiterThread.join(timeoutMillis)
        return signalled && !readerThread.isAlive && !waiterThread.isAlive
    }

    /**
     * Number of packets dropped because the worker queue was full.
     */
    fun droppedPackets(): Long = droppedPackets.get()

    /**
     * Number of TCP packets addressed to the DNS port; they cannot be served by this tunnel.
     */
    fun tcpPackets(): Long = tcpPackets.get()

    /**
     * Number of answers written back to the client.
     */
    fun answeredPackets(): Long = answeredPackets.get()

    private fun awaitShutdown() {
        shutdownLatch.await()
        closeQuietly(input)
        tcpRelay?.closeAll()
        udpRelay?.closeAll()
        executor.shutdownNow()
        executor.awaitTermination(SHUTDOWN_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        state = TunnelState.Idle
    }

    private fun readLoop() {
        val buffer = ByteArray(MAX_PACKET_SIZE)

        while (state == TunnelState.Running) {
            val size = try {
                input.read(buffer)
            } catch (exception: IOException) {
                break
            }
            if (size < 0) break // end of stream: the descriptor was closed
            if (size == 0) continue

            val packet = buffer.copyOf(size)
            try {
                executor.execute(Runnable { handle(packet) })
            } catch (exception: RejectedExecutionException) {
                droppedPackets.incrementAndGet()
            }
        }
    }

    private fun handle(packet: ByteArray) {
        if (fullTunnel) {
            handleFullTunnel(packet)
            return
        }
        val parsed = Ipv4UdpCodec.parseIpv4Udp(packet)
        if (parsed == null) {
            if (isTcpToDnsPort(packet)) tcpPackets.incrementAndGet()
            return
        }
        // Encrypted DNS to a known resolver is dropped before the plain-DNS port check; otherwise a
        // query to port 853/443 would be rejected by the port check below and the strict rule would
        // never run. TCP to those ports is dropped by parseIpv4Udp returning null.
        if (StrictResolverIps.isStrictResolver(parsed.destinationAddress) &&
            StrictResolverIps.isDroppedPort(parsed.destinationPort)
        ) {
            return
        }
        if (parsed.destinationPort != DNS_PORT) return

        val response = responder.respond(parsed.payload) ?: return
        val answer = Ipv4UdpCodec.buildIpv4UdpResponse(parsed, response)

        synchronized(outputLock) {
            try {
                output.write(answer)
                output.flush()
            } catch (exception: IOException) {
                return
            }
        }
        answeredPackets.incrementAndGet()
    }

    /**
     * Full-tunnel dispatch: DNS is still answered locally by the policy engine, while other UDP and
     * all TCP flows are relayed through protected sockets. Encrypted DNS to known resolvers is
     * dropped by the relay; DoH to arbitrary hosts is stopped through TLS SNI inspection.
     */
    private fun handleFullTunnel(packet: ByteArray) {
        val udp = Ipv4UdpCodec.parseIpv4Udp(packet)
        if (udp != null) {
            if (StrictResolverIps.isStrictResolver(udp.destinationAddress) &&
                StrictResolverIps.isDroppedPort(udp.destinationPort)
            ) {
                return
            }
            if (udp.destinationPort == 53) {
                val response = responder.respond(udp.payload) ?: return
                writeAnswer(packet, Ipv4UdpCodec.buildIpv4UdpResponse(udp, response))
                return
            }
            udpRelay?.handle(udp)
            return
        }

        val tcp = Ipv4TcpCodec.parse(packet) ?: return
        if (StrictResolverIps.isStrictResolver(tcp.destinationAddress) &&
            StrictResolverIps.isDroppedPort(tcp.destinationPort)
        ) {
            writePacketAsync(Ipv4TcpCodec.reset(tcp))
            return
        }
        tcpRelay?.handle(tcp)
    }

    private fun writeAnswer(original: ByteArray, answer: ByteArray) {
        writePacketAsync(answer)
    }

    private fun writePacketAsync(packet: ByteArray) {
        synchronized(outputLock) {
            try {
                output.write(packet)
                output.flush()
            } catch (exception: IOException) {
                return
            }
        }
        answeredPackets.incrementAndGet()
    }

    private fun isTcpToDnsPort(packet: ByteArray): Boolean {
        if (packet.size < IPV4_MIN_HEADER) return false
        if ((packet[0].toInt() and 0xF0) != 0x40) return false
        if (packet[9].toInt() != PROTOCOL_TCP) return false

        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ipHeaderLength + 4) return false

        val destinationPort =
            ((packet[ipHeaderLength + 2].toInt() and 0xFF) shl 8) or (packet[ipHeaderLength + 3].toInt() and 0xFF)
        return destinationPort == DNS_PORT
    }

    private fun closeQuietly(stream: InputStream) {
        try {
            stream.close()
        } catch (exception: IOException) {
            // the reader thread is already leaving
        }
    }

    companion object {
        /** Port the virtual DNS server listens on inside the tunnel. */
        const val DNS_PORT: Int = 53

        /** Number of worker threads answering the queries. */
        const val WORKER_COUNT: Int = 8

        /** Maximum number of queries waiting to be answered. */
        const val PENDING_LIMIT: Int = 1024

        /** Maximum size of a packet read from the tunnel. */
        const val MAX_PACKET_SIZE: Int = 32767

        private const val IPV4_MIN_HEADER: Int = 20
        private const val PROTOCOL_TCP: Int = 6
        private const val SHUTDOWN_TIMEOUT_MILLIS: Long = 2000L
        private const val READER_THREAD_NAME: String = "blockermod-dns-reader"
        private const val WAITER_THREAD_NAME: String = "blockermod-dns-waiter"
        private const val WORKER_THREAD_NAME: String = "blockermod-dns-worker"
    }
}
