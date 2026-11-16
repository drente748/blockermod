package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsTypes
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger

/**
 * Binds an outgoing socket to the physical network so that it never enters the tunnel.
 *
 * On Android the file descriptor of a [DatagramSocket] is not reachable, so the network aware
 * binding is used instead of the descriptor based protection. The socket is always bound before
 * it is connected.
 */
internal fun interface SocketBinder {

    /** @return true when the socket was bound to the physical network and may be used. */
    fun bind(socket: DatagramSocket): Boolean
}

/** Source of the records of a host. */
internal interface DnsUpstream {

    /** Returns the response code and records of the host and type. */
    fun lookup(host: String, type: Int): DnsWire.Answer
}

/**
 * A single UDP socket reused for every upstream exchange.
 *
 * Creating a socket per query is expensive on Android: each creation binds a file descriptor,
 * triggers a binder call to the network service, and adds GC pressure on every DNS lookup. One
 * long-lived socket bound to the physical network removes all of that, which is a direct battery
 * and latency win. The socket is rebound when the active network changes, and a failed exchange
 * invalidates it so the next attempt recreates it.
 */
internal class ReusableDnsSocket(
    private val binder: SocketBinder,
) : AutoCloseable {

    @Volatile
    private var socket: DatagramSocket? = null

    @Volatile
    private var boundNetwork: Any? = null

    /** Opaque identity of the physical network the current socket is bound to. */
    fun boundNetwork(): Any? = boundNetwork

    /** Sends one query to [server] and returns the raw response, or null when the exchange fails. */
    @Synchronized
    fun exchange(query: ByteArray, server: InetAddress, network: Any?, timeoutMillis: Int): ByteArray? {
        val current = socket
        if (current == null || current.isClosed || network != boundNetwork) {
            closeSocket()
            if (network == null) return null
            val created = try {
                DatagramSocket()
            } catch (exception: IOException) {
                return null
            }
            if (!binder.bind(created)) {
                try { created.close() } catch (ignored: Exception) {}
                return null
            }
            socket = created
            boundNetwork = network
        }

        val active = socket ?: return null
        return try {
            active.soTimeout = timeoutMillis
            active.connect(InetSocketAddress(server, UpstreamResolver.DNS_PORT))
            active.send(DatagramPacket(query, query.size, server, UpstreamResolver.DNS_PORT))

            val buffer = ByteArray(UpstreamResolver.MAX_RESPONSE_SIZE)
            val packet = DatagramPacket(buffer, buffer.size)
            active.receive(packet)
            val response = packet.data.copyOf(packet.length)

            if (!isMatchingResponse(query, response)) return null
            response
        } catch (exception: IOException) {
            closeSocket()
            null
        }
    }

    override fun close() = closeSocket()

    private fun closeSocket() {
        try {
            socket?.close()
        } catch (ignored: Exception) {
            // already closed
        }
        socket = null
        boundNetwork = null
    }

    private fun isMatchingResponse(query: ByteArray, response: ByteArray): Boolean {
        if (query.size < 2 || response.size < 12) return false
        val sameId = query[0] == response[0] && query[1] == response[1]
        val isResponse = response[2].toInt() and 0x80 != 0
        return sameId && isResponse
    }
}

/**
 * Plain DNS forwarder to the servers of the active network.
 *
 * Caching, negative caching, policy and CNAME walking live in [LocalDnsResolver]; this class only
 * performs the network exchange, which keeps the two concerns separate and testable.
 */
internal class UpstreamResolver(
    private val socketBinder: SocketBinder,
    private val upstreamServers: () -> List<InetAddress>,
    private val activeNetwork: () -> Any?,
    private val timeoutMillis: Int = TIMEOUT_MILLIS,
) : DnsUpstream, AutoCloseable {

    private val socket = ReusableDnsSocket(socketBinder)

    override fun lookup(host: String, type: Int): DnsWire.Answer {
        val response = exchange(DnsWire.buildQuery(nextId(), host, type))
            ?: return DnsWire.Answer(DnsWire.RCODE_SERVFAIL, emptyList())

        val rcode = DnsWire.responseRcode(response)
        if (rcode != DnsWire.RCODE_NOERROR) {
            return DnsWire.Answer(rcode, emptyList())
        }

        val records = DnsWire.parseAnswers(response)
            .filter { it.type == type || it.type == DnsTypes.CNAME }
        return DnsWire.Answer(DnsWire.RCODE_NOERROR, records)
    }

    /** Sends a raw query to the upstream servers and returns the raw answer. */
    fun exchange(query: ByteArray): ByteArray? {
        val network = activeNetwork()
        for (server in upstreamServers()) {
            socket.exchange(query, server, network, timeoutMillis)?.let { return it }
        }
        return null
    }

    override fun close() = socket.close()

    private fun nextId(): Int = IDS.incrementAndGet() and 0xFFFF

    companion object {
        const val DNS_PORT: Int = 53
        const val TIMEOUT_MILLIS: Int = 4000
        const val MAX_RESPONSE_SIZE: Int = 4096
        const val NEGATIVE_TTL_SECONDS: Long = 60L
        private val IDS = AtomicInteger(1)
    }
}
