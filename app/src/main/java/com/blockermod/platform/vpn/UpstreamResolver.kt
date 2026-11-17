package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsTcpExchange
import com.blockermod.core.dns.DnsTcpTransport
import com.blockermod.core.dns.DnsTypes
import com.blockermod.core.dns.extractQuestion
import com.blockermod.core.dns.sameQuestion
import com.blockermod.core.dns.frameDnsTcp
import com.blockermod.core.dns.isDnsTruncated
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
    fun exchange(
        query: ByteArray,
        server: InetAddress,
        network: Any?,
        timeoutMillis: Int,
        port: Int = UpstreamResolver.DNS_PORT,
    ): ByteArray? {
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
            active.connect(InetSocketAddress(server, port))
            active.send(DatagramPacket(query, query.size, server, port))

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
        // Match the question section as well (case-insensitive), consistent with the TCP path.
        return sameId && isResponse && sameQuestion(extractQuestion(query), extractQuestion(response))
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
    private val tcpProtect: (java.net.Socket) -> Boolean,
    private val upstreamServers: () -> List<InetAddress>,
    private val activeNetwork: () -> Any?,
    private val timeoutMillis: Int = TIMEOUT_MILLIS,
    private val tcpTimeoutMillis: Int = TCP_TIMEOUT_MILLIS,
    private val dnsPort: Int = DNS_PORT,
) : DnsUpstream, AutoCloseable {

    private val socket = ReusableDnsSocket(socketBinder)
    // A single absolute deadline per TCP exchange, never renewed on each read.
    private val tcpExchange = DnsTcpExchange(readTimeoutMillis = tcpTimeoutMillis)

    override fun lookup(host: String, type: Int): DnsWire.Answer {
        val query = DnsWire.buildQuery(nextId(), host, type)
        var response = exchange(query)
            ?: return DnsWire.Answer(DnsWire.RCODE_SERVFAIL, emptyList())

        // RFC 7766 §5 / RFC 9210 §3: a truncated UDP answer MUST be retried over TCP.
        if (isDnsTruncated(response)) {
            val network = activeNetwork()
            val servers = upstreamServers()
            for (server in servers) {
                val transport = openTcpTransport(server, network) ?: continue
                transport.use { candidate ->
                    when (val outcome = tcpExchange.exchange(candidate, query)) {
                        is DnsTcpExchange.Outcome.Message -> {
                            response = outcome.bytes
                            return@use
                        }
                        else -> {} // try the next server
                    }
                }
                // A message with the matching ID was received; stop trying other servers.
                if (!isDnsTruncated(response)) break
            }
            if (isDnsTruncated(response)) return DnsWire.Answer(DnsWire.RCODE_SERVFAIL, emptyList())
        }

        val rcode = DnsWire.responseRcode(response)
        if (rcode != DnsWire.RCODE_NOERROR) {
            return DnsWire.Answer(rcode, emptyList())
        }

        val records = DnsWire.parseAnswers(response)
            .filter { it.type == type || it.type == DnsTypes.CNAME }
        return DnsWire.Answer(DnsWire.RCODE_NOERROR, records)
    }

    /** Opens a protected TCP socket for DNS retry; closed by the caller. */
    private fun openTcpTransport(server: InetAddress, network: Any?): DnsTcpTransport? {
        if (network == null) return null
        var raw: java.net.Socket? = null
        return try {
            raw = java.net.Socket()
            // protect() is called through the same binder used by relays: never let the retry
            // socket re-enter the VPN.
            if (!tcpProtect(raw)) throw IOException("socket could not be protected")
            raw.soTimeout = tcpTimeoutMillis
            raw.connect(InetSocketAddress(server, dnsPort), tcpTimeoutMillis)
            raw.tcpNoDelay = true
            val socket = raw
            object : DnsTcpTransport {
                override val input: java.io.InputStream = socket.getInputStream()
                override val output: java.io.OutputStream = socket.getOutputStream()
                override fun setReadTimeout(millis: Int) { socket.soTimeout = millis }
                override fun close() = socket.close()
            }
        } catch (exception: IOException) {
            // A failed protect/connect still allocates an fd; never leak it.
            try { raw?.close() } catch (ignored: Exception) {}
            null
        }
    }

    /** Sends a raw query to the upstream servers and returns the raw answer. */
    fun exchange(query: ByteArray): ByteArray? {
        val network = activeNetwork()
        for (server in upstreamServers()) {
            socket.exchange(query, server, network, timeoutMillis, dnsPort)?.let { return it }
        }
        return null
    }

    override fun close() = socket.close()

    private fun nextId(): Int = IDS.incrementAndGet() and 0xFFFF

    companion object {
        const val DNS_PORT: Int = 53
        const val TIMEOUT_MILLIS: Int = 4000
        const val MAX_RESPONSE_SIZE: Int = 4096
        const val TCP_TIMEOUT_MILLIS: Int = 3_000
        const val NEGATIVE_TTL_SECONDS: Long = 60L
        private val IDS = AtomicInteger(1)
    }
}
