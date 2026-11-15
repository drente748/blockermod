package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsRecord
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

    /**
     * Binds the socket to the physical network.
     *
     * @return true when the socket was bound and may be used.
     */
    fun bind(socket: DatagramSocket): Boolean
}

/**
 * Source of the records of a host.
 */
internal interface DnsUpstream {

    /**
     * Returns the records of the host and type, from the cache when possible.
     */
    fun lookup(host: String, type: Int): List<DnsRecord>
}

/**
 * Resolver that talks plain UDP DNS to the servers of the active network.
 *
 * Answers are cached in a [DnsCache]; only answers of allowed domains are stored because blocked
 * domains are never resolved.
 */
internal class UpstreamResolver(
    private val cache: DnsCache,
    private val socketBinder: SocketBinder,
    private val upstreamServers: () -> List<InetAddress>,
    private val timeoutMillis: Int = TIMEOUT_MILLIS,
) : DnsUpstream {

    /**
     * Returns the records of the host and type, from the cache when possible.
     */
    override fun lookup(host: String, type: Int): List<DnsRecord> {
        val key = cacheKey(host, type)
        cache.get(key)?.let { return it }

        val response = exchange(DnsWire.buildQuery(nextId(), host, type)) ?: return emptyList()
        val records = DnsWire.parseAnswers(response)
            .filter { it.type == type || it.type == DnsTypes.CNAME }
        if (records.isEmpty()) return emptyList()

        cache.put(key, records, records.minOf { it.ttlSeconds })
        return records
    }

    /**
     * Sends a raw query to the upstream servers and returns the raw answer.
     *
     * Returns null when every server failed or timed out.
     */
    fun exchange(query: ByteArray): ByteArray? {
        for (server in upstreamServers()) {
            val socket = try {
                DatagramSocket()
            } catch (exception: IOException) {
                continue
            }

            try {
                if (!socketBinder.bind(socket)) continue
                socket.soTimeout = timeoutMillis
                socket.connect(InetSocketAddress(server, DNS_PORT))
                socket.send(DatagramPacket(query, query.size, server, DNS_PORT))

                val buffer = ByteArray(MAX_RESPONSE_SIZE)
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)

                return packet.data.copyOf(packet.length)
            } catch (exception: IOException) {
                continue
            } finally {
                socket.close()
            }
        }

        return null
    }

    private fun cacheKey(host: String, type: Int): String = "$host/$type"

    private fun nextId(): Int = IDS.incrementAndGet() and 0xFFFF

    companion object {
        /** Port of the upstream DNS servers. */
        const val DNS_PORT: Int = 53

        /** Timeout of an upstream exchange, in milliseconds. */
        const val TIMEOUT_MILLIS: Int = 4000

        /** Maximum size of an upstream answer. */
        const val MAX_RESPONSE_SIZE: Int = 4096

        private val IDS = AtomicInteger(1)
    }
}
