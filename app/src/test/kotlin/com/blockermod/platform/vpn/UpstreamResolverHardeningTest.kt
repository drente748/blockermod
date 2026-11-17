package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsTypes
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Regressions for the upstream query id, socket reuse pool and absolute deadline (B7). */
class UpstreamResolverHardeningTest {

    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")

    private fun resolver(port: Int, total: Int = 4_000, tcp: Int = 3_000) = UpstreamResolver(
        socketBinder = { true },
        tcpProtect = { true },
        upstreamServers = { listOf(loopback) },
        activeNetwork = { "test-network" },
        timeoutMillis = 2_000,
        tcpTimeoutMillis = tcp,
        dnsPort = port,
        totalTimeoutMillis = total,
    )

    @Test
    fun `query ids are not sequential`() {
        val resolver = resolver(port = 0)
        try {
            val ids = (1..40).map { resolver.nextId() }
            val consecutive = ids.zipWithNext().count { (a, b) -> b == (a + 1) and 0xFFFF }

            assertTrue(consecutive < ids.size / 2, "predictable sequential ids are unsafe")
            assertTrue(ids.toSet().size > 30, "ids must be distinct in practice")
        } finally {
            resolver.close()
        }
    }

    @Test
    fun `concurrent lookups are not serialized on one socket`() {
        val udp = DatagramSocket(0, loopback).apply { soTimeout = 3_000 }
        val port = udp.localPort
        val received = AtomicInteger(0)
        val server = Thread {
            val requests = ArrayList<DatagramPacket>()
            try {
                repeat(2) {
                    val buffer = ByteArray(512)
                    val request = DatagramPacket(buffer, buffer.size)
                    udp.receive(request)
                    received.incrementAndGet()
                    requests += request
                }
                // Reply only after BOTH queries arrived: one shared socket would block in receive()
                // on the first query and the second query could never be sent.
                requests.forEach { request ->
                    val response = DnsCodec.buildNoData(DnsCodec.parseQuery(request.data.copyOf(request.length))!!)
                    udp.send(DatagramPacket(response, response.size, request.address, request.port))
                }
            } catch (ignored: Exception) {
            }
        }.apply { isDaemon = true }
        val resolver = resolver(port)
        val start = CountDownLatch(1)
        val workers = (1..2).map { index ->
            Thread {
                start.await()
                resolver.lookup("pool$index.example", DnsTypes.A)
            }.apply { isDaemon = true; start() }
        }
        try {
            server.start()
            start.countDown()
            workers.forEach { it.join(5_000) }
            server.join(5_000)

            assertEquals(2, received.get(), "both lookups must be in flight before any reply")
        } finally {
            resolver.close()
            udp.close()
        }
    }

    @Test
    fun `the total deadline bounds a silent tcp retry`() {
        val udp = DatagramSocket(0, loopback).apply { soTimeout = 3_000 }
        val port = udp.localPort
        val udpServer = Thread {
            try {
                val buffer = ByteArray(512)
                val request = DatagramPacket(buffer, buffer.size)
                udp.receive(request)
                val truncated = request.data.copyOf(request.length).also { it[2] = (it[2].toInt() or 0x82).toByte() }
                udp.send(DatagramPacket(truncated, truncated.size, request.address, request.port))
            } catch (ignored: Exception) {
            }
        }.apply { isDaemon = true }
        val silentTcp = ServerSocket(port, 1, loopback).apply { soTimeout = 3_000 }
        val tcpServer = Thread {
            try {
                val client = silentTcp.accept()
                client.getInputStream().read() // accept the query, then never answer
                Thread.sleep(2_000)
                client.close()
            } catch (ignored: Exception) {
            }
        }.apply { isDaemon = true }
        val resolver = resolver(port, total = 400, tcp = 3_000)
        try {
            udpServer.start()
            tcpServer.start()
            val started = System.nanoTime()
            val answer = resolver.lookup("deadline.example", DnsTypes.A)
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

            assertEquals(DnsWire.RCODE_SERVFAIL, answer.rcode)
            assertTrue(elapsed < 1_500, "total deadline must cut the retry short (elapsed=$elapsed ms)")
        } finally {
            resolver.close()
            udp.close()
            silentTcp.close()
        }
    }
}
