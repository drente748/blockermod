package com.blockermod.platform.vpn

import com.blockermod.core.dns.extractQuestion
import com.blockermod.core.dns.sameQuestion
import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * End-to-end test of the upstream path: UDP query -> TC=1 truncated answer -> TCP retry -> full answer.
 * Uses real loopback sockets (JVM only, no Android) and asserts query identity, QR bit, question
 * match, socket closure and that the truncated UDP answer is never returned as complete.
 */
class DnsTcpRetryIntegrationTest {

    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")
    private val distinctiveAddress = 0xCB007107.toInt() // 203.0.113.7 (bit pattern)

    @Test
    fun `truncated udp answer is retried over tcp and the full answer is used`() {
        val udpLatch = CountDownLatch(1)
        val tcpLatch = CountDownLatch(1)
        val udpId = AtomicReference<Int>(-1)
        val tcpId = AtomicReference<Int>(-1)
        val tcpQuestion = AtomicReference<ByteArray>(null)
        val udpQuestion = AtomicReference<ByteArray>(null)
        val createdTcpSockets = ArrayList<Socket>()

        val udp = DatagramSocket(0, loopback).apply { soTimeout = 3000 }
        val port = udp.localPort
        val tcp = ServerSocket(port, 1, loopback).apply { soTimeout = 3000 }

        val udpServer = Thread {
            try {
                val buffer = ByteArray(2048)
                val request = DatagramPacket(buffer, buffer.size)
                udp.receive(request)
                val query = request.data.copyOf(request.length)
                udpId.set(readU16(query, 0))
                udpQuestion.set(extractQuestion(query))
                // Reply with TC=1 and NO answers: the client MUST retry over TCP.
                val truncated = buildResponse(udpId.get(), extractQuestion(query) ?: ByteArray(0), truncated = true, emptyList())
                udp.send(DatagramPacket(truncated, truncated.size, request.address, request.port))
            } catch (ignored: Exception) {
            } finally {
                udpLatch.countDown()
            }
        }.apply { isDaemon = true }

        val tcpServer = Thread {
            try {
                val client = tcp.accept()
                val lengthBytes = ByteArray(2)
                readFully(client, lengthBytes)
                val length = ((lengthBytes[0].toInt() and 0xFF) shl 8) or (lengthBytes[1].toInt() and 0xFF)
                val query = ByteArray(length)
                readFully(client, query)
                tcpId.set(readU16(query, 0))
                tcpQuestion.set(extractQuestion(query))
                val full = buildResponse(tcpId.get(), extractQuestion(query) ?: ByteArray(0), truncated = false, listOf(distinctiveAddress))
                client.getOutputStream().write(byteArrayOf((full.size ushr 8).toByte(), full.size.toByte()) + full)
                client.getOutputStream().flush()
                client.close()
            } catch (ignored: Exception) {
            } finally {
                tcpLatch.countDown()
            }
        }.apply { isDaemon = true }

        val resolver = UpstreamResolver(
            socketBinder = { true },
            tcpProtect = { socket -> synchronized(createdTcpSockets) { createdTcpSockets.add(socket) }; true },
            upstreamServers = { listOf(loopback) },
            activeNetwork = { "loopback-test-network" },
            timeoutMillis = 1000,
            tcpTimeoutMillis = 1500,
            dnsPort = port,
        )

        try {
            udpServer.start()
            tcpServer.start()

            val answer = resolver.lookup("retry.example", DnsTypes.A)

            assertTrue(udpLatch.await(3, TimeUnit.SECONDS), "UDP server must be queried")
            assertTrue(tcpLatch.await(3, TimeUnit.SECONDS), "TCP retry must happen")

            // Original query identity and question were reused on the TCP connection.
            assertEquals(udpId.get(), tcpId.get(), "TCP retry must use the original Message ID")
            assertTrue(udpId.get() >= 0, "a real ID must have been generated")
            assertTrue(sameQuestion(udpQuestion.get(), tcpQuestion.get()), "TCP query must carry the same question")

            // The full TCP answer is used, not the truncated UDP one.
            assertEquals(DnsWire.RCODE_NOERROR, answer.rcode)
            assertTrue(answer.records.any { it.type == DnsTypes.A && it.data.size == 4 && readU32(it.data) == distinctiveAddress },
                "the A record from the TCP answer must be returned")
        } finally {
            resolver.close()
            udp.close()
            tcp.close()
        }

        // Every protected TCP socket opened by the retry is closed (success path).
        synchronized(createdTcpSockets) {
            assertTrue(createdTcpSockets.isNotEmpty(), "a TCP socket must have been opened")
            assertTrue(createdTcpSockets.all { it.isClosed }, "all TCP sockets must be closed after the exchange")
        }
    }

    @Test
    fun `unavailable tcp server returns servfail and closes the socket`() {
        val udpLatch = CountDownLatch(1)
        val createdTcpSockets = ArrayList<Socket>()
        val udp = DatagramSocket(0, loopback).apply { soTimeout = 3000 }
        val port = udp.localPort
        // Reserve then immediately close the TCP port so connect() is refused.
        ServerSocket(port, 1, loopback).close()

        val udpServer = Thread {
            try {
                val buffer = ByteArray(2048)
                val request = DatagramPacket(buffer, buffer.size)
                udp.receive(request)
                val query = request.data.copyOf(request.length)
                val truncated = buildResponse(readU16(query, 0), extractQuestion(query) ?: ByteArray(0), true, emptyList())
                udp.send(DatagramPacket(truncated, truncated.size, request.address, request.port))
            } catch (ignored: Exception) {
            } finally {
                udpLatch.countDown()
            }
        }.apply { isDaemon = true }

        val resolver = UpstreamResolver(
            socketBinder = { true },
            tcpProtect = { socket -> synchronized(createdTcpSockets) { createdTcpSockets.add(socket) }; true },
            upstreamServers = { listOf(loopback) },
            activeNetwork = { "loopback-test-network" },
            timeoutMillis = 1000,
            tcpTimeoutMillis = 500,
            dnsPort = port,
        )

        try {
            udpServer.start()
            val answer = resolver.lookup("retry.example", DnsTypes.A)
            assertTrue(udpLatch.await(3, TimeUnit.SECONDS))
            // The truncated UDP answer must NOT be returned as a complete answer.
            assertEquals(DnsWire.RCODE_SERVFAIL, answer.rcode)
            assertTrue(answer.records.isEmpty())
        } finally {
            resolver.close()
            udp.close()
        }

        synchronized(createdTcpSockets) {
            assertTrue(createdTcpSockets.isNotEmpty(), "a TCP retry must have been attempted")
            assertTrue(createdTcpSockets.all { it.isClosed }, "even a failed TCP socket must be closed")
        }
    }

    private fun buildResponse(id: Int, question: ByteArray, truncated: Boolean, addresses: List<Int>): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, id)
        // QR=1, RD=1, RA=1, rcode=0; add TC (0x0200) when truncated.
        val flags = 0x8180 or if (truncated) 0x0200 else 0
        writeU16(out, flags)
        writeU16(out, 1) // QDCOUNT
        writeU16(out, if (truncated) 0 else addresses.size)
        writeU16(out, 0) // NSCOUNT
        writeU16(out, 0) // ARCOUNT
        out.write(question)
        for (address in addresses) {
            out.write(0xC0); out.write(0x0C) // pointer to the question name at offset 12
            writeU16(out, DnsTypes.A)
            writeU16(out, 1) // class IN
            out.write(0); out.write(0); out.write(0); out.write(60) // TTL
            writeU16(out, 4) // RDLEN
            out.write((address ushr 24) and 0xFF)
            out.write((address ushr 16) and 0xFF)
            out.write((address ushr 8) and 0xFF)
            out.write(address and 0xFF)
        }
        return out.toByteArray()
    }

    private fun readFully(socket: Socket, target: ByteArray) {
        var offset = 0
        val input = socket.getInputStream()
        while (offset < target.size) {
            val count = input.read(target, offset, target.size - offset)
            if (count < 0) throw java.io.EOFException()
            offset += count
        }
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun readU32(bytes: ByteArray): Int =
        ((bytes[0].toInt() and 0xFF) shl 24) or ((bytes[1].toInt() and 0xFF) shl 16) or
            ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
