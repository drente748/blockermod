package com.blockermod.platform.vpn

import com.blockermod.core.DomainMatcher
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import com.blockermod.core.policy.TransportPolicy
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Lifecycle tests for the full-tunnel TCP relay. Packets are real IPv4/TCP buffers; no Android and
 * no sockets are exercised (test cases deliberately stay on paths that do not open a network
 * connection, because android.util.Log is a stub in local unit tests).
 */
class TcpRelayTest {

    private val written = ByteArrayOutputStream()
    private var blocked = 0
    private val noDomains = object : DomainMatcher {
        override fun matches(domain: String) = false
    }

    private fun policy(blocker: DomainMatcher = noDomains) = TransportPolicy(
        isKnownEncryptedResolver = { false },
        dohHosts = blocker,
    )

    private fun relay(now: () -> Long = { 0L }) = TcpRelay(
        protectSocket = { true },
        writePacket = { written.write(it) },
        transportPolicy = policy(),
        onDohBlocked = { blocked++ },
        nowMillis = now,
    )

    @Test
    fun `server data honors the client receive window`() {
        val relay = relay()
        val syn = seg(seq = 100L, flags = Ipv4TcpCodec.Flags.SYN)
        relay.handle(syn)
        val connection = relay.findConnection(syn)!!
        val data = ByteArray(5000) { 1 }

        // A closed window parks the pump: no segment may be injected.
        relay.handle(seg(seq = 101L, window = 0))
        written.reset()
        relay.injectServerData(connection, data)
        assertEquals(0, packets().size, "zero window must inject nothing")

        // A small window emits at most that many bytes and retains the rest for a later ACK.
        relay.handle(seg(seq = 101L, window = 100))
        written.reset()
        relay.injectServerData(connection, data)
        val emitted = packets().sumOf { it.payload.size }
        assertTrue(emitted in 1..100, "only the advertised window may be injected (was $emitted)")
        assertTrue(connection.send.pendingByteCount() > 0, "unemitted bytes stay queued")
    }

    @Test
    fun `syn is answered with syn ack and registers a connection`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, flags = Ipv4TcpCodec.Flags.SYN))

        val reply = packets().single()
        assertEquals(Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK, reply.flags)
        assertEquals(101L, reply.acknowledgmentNumber)
        assertEquals(1, relay.connectionCount())
    }

    @Test
    fun `retransmitted syn does not replace the live connection`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, flags = Ipv4TcpCodec.Flags.SYN))
        written.reset()
        relay.handle(seg(seq = 100L, flags = Ipv4TcpCodec.Flags.SYN))

        assertEquals(1, relay.connectionCount())
        val replies = packets()
        assertEquals(1, replies.size)
        // A retransmitted SYN must be answered with SYN-ACK, not a bare ACK, so the client can
        // complete the handshake when the original SYN-ACK was lost.
        assertEquals(
            Ipv4TcpCodec.Flags.SYN or Ipv4TcpCodec.Flags.ACK,
            replies[0].flags and 0x3F,
        )
    }

    @Test
    fun `ack before syn is reset`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, flags = Ipv4TcpCodec.Flags.ACK))

        assertEquals(0, relay.connectionCount())
        assertEquals(Ipv4TcpCodec.Flags.RST, packets().single().flags and Ipv4TcpCodec.Flags.RST)
    }

    @Test
    fun `rst removes the connection`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, flags = Ipv4TcpCodec.Flags.SYN))
        relay.handle(seg(seq = 101L, flags = Ipv4TcpCodec.Flags.RST))

        assertEquals(0, relay.connectionCount())
    }

    @Test
    fun `fin closes the connection and emits fin ack`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, flags = Ipv4TcpCodec.Flags.SYN))
        written.reset()
        relay.handle(seg(seq = 101L, flags = Ipv4TcpCodec.Flags.FIN or Ipv4TcpCodec.Flags.ACK))

        assertEquals(0, relay.connectionCount())
        assertTrue(packets().any { it.flags and Ipv4TcpCodec.Flags.FIN != 0 })
    }

    @Test
    fun `out of order segment is acked with the expected sequence`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, port = 443, flags = Ipv4TcpCodec.Flags.SYN))
        written.reset()
        relay.handle(seg(seq = 500L, port = 443, flags = Ipv4TcpCodec.Flags.ACK, payload = partialTls()))

        val ack = packets().single()
        assertEquals(101L, ack.acknowledgmentNumber)
    }

    @Test
    fun `duplicate segment is acked once and not forwarded`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, port = 443, flags = Ipv4TcpCodec.Flags.SYN))
        written.reset()
        val data = partialTls()
        relay.handle(seg(seq = 101L, port = 443, flags = Ipv4TcpCodec.Flags.ACK, payload = data))
        relay.handle(seg(seq = 101L, port = 443, flags = Ipv4TcpCodec.Flags.ACK, payload = data))

        // First segment produces no output (TLS decision pending); only the duplicate is ACKed.
        assertEquals(1, packets().size)
    }

    @Test
    fun `a client hello split across segments is still detected and blocked`() {
        val doh = object : DomainMatcher {
            override fun matches(domain: String) = domain == "dns.google"
        }
        val written2 = ByteArrayOutputStream()
        val relay = TcpRelay(
            protectSocket = { true },
            writePacket = { written2.write(it) },
            transportPolicy = policy(doh),
            onDohBlocked = { blocked++ },
            nowMillis = { 0L },
        )
        val hello = clientHello("dns.google")
        val split = hello.size / 2

        relay.handle(seg(seq = 100L, port = 443, flags = Ipv4TcpCodec.Flags.SYN))
        relay.handle(seg(seq = 101L, port = 443, flags = Ipv4TcpCodec.Flags.ACK, payload = hello.copyOfRange(0, split)))
        assertEquals(0, blocked, "a partial ClientHello must not trigger a decision")

        relay.handle(seg(seq = 101L + split, port = 443, flags = Ipv4TcpCodec.Flags.ACK, payload = hello.copyOfRange(split, hello.size)))

        assertEquals(1, blocked, "the assembled ClientHello must be recognized as DoH")
        assertEquals(0, relay.connectionCount())
    }

    @Test
    fun `dot on tcp 853 is reset through the transport policy`() {
        val relay = relay()
        relay.handle(seg(seq = 100L, port = 853, flags = Ipv4TcpCodec.Flags.SYN))

        assertEquals(0, relay.connectionCount(), "no connection may stay open to port 853")
        val reply = packets().single()
        assertEquals(Ipv4TcpCodec.Flags.RST or Ipv4TcpCodec.Flags.ACK, reply.flags and 0x3F)
        assertEquals(1, blocked, "the reset counts as a blocked bypass attempt")
    }

    /** Minimal structurally-valid ClientHello carrying one SNI extension. */
    private fun clientHello(host: String): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val name = byteArrayOf(0x00) + u16(hostBytes.size) + hostBytes
        val sni = u16(0) + u16(name.size + 2) + u16(name.size) + name
        val body = u16(0x0303) + ByteArray(32) + byteArrayOf(0) +
            u16(2) + byteArrayOf(0x13, 0x01) + byteArrayOf(1, 0) + u16(sni.size) + sni
        val handshake = byteArrayOf(0x01, (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
        return byteArrayOf(0x16, 0x03, 0x03) + u16(handshake.size) + handshake
    }

    private fun u16(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())

    @Test
    fun `connection table is bounded`() {
        val relay = relay()
        for (port in 20_000 until 21_000) {
            relay.handle(seg(seq = 1L, port = port, flags = Ipv4TcpCodec.Flags.SYN))
        }
        // The cap is 128 regardless of how many SYNs arrive.
        assertEquals(128, relay.connectionCount())
    }

    @Test
    fun `idle connection is reaped on subsequent activity`() {
        var now = 0L
        val relay = relay(now = { now })
        relay.handle(seg(seq = 1L, port = 20_000, flags = Ipv4TcpCodec.Flags.SYN))
        relay.handle(seg(seq = 1L, port = 443, flags = Ipv4TcpCodec.Flags.SYN))
        assertEquals(2, relay.connectionCount())

        now = 70_000L
        // Activity on the port-443 flow refreshes it and reaps the idle 20_000 flow.
        relay.handle(seg(seq = 2L, port = 443, flags = Ipv4TcpCodec.Flags.ACK, payload = partialTls()))

        assertEquals(1, relay.connectionCount())
    }

    @Test
    fun `closeAll drops every connection`() {
        val relay = relay()
        relay.handle(seg(seq = 1L, port = 20_000, flags = Ipv4TcpCodec.Flags.SYN))
        relay.handle(seg(seq = 1L, port = 20_001, flags = Ipv4TcpCodec.Flags.SYN))

        relay.closeAll()

        assertEquals(0, relay.connectionCount())
    }

    private fun packets(): List<Ipv4TcpPacket> {
        val bytes = written.toByteArray()
        val result = ArrayList<Ipv4TcpPacket>()
        var offset = 0
        while (offset < bytes.size) {
            val packet = Ipv4TcpCodec.parse(bytes.copyOfRange(offset, bytes.size)) ?: break
            result += packet
            offset += packet.ipHeaderLength + packet.tcpHeaderLength + packet.payload.size
        }
        return result
    }

    /** A partial ClientHello keeps TLS inspection UNKNOWN, so no upstream socket is opened. */
    private fun partialTls(): ByteArray =
        byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x40, 0x01) + ByteArray(20)

    private fun seg(
        seq: Long,
        port: Int = 44_444,
        flags: Int = Ipv4TcpCodec.Flags.ACK,
        payload: ByteArray = ByteArray(0),
        window: Int = 65_535,
    ): Ipv4TcpPacket = Ipv4TcpPacket(
        sourceAddress = 0x0A000001,
        destinationAddress = 0x0A000002,
        sourcePort = 40_000,
        destinationPort = port,
        sequenceNumber = seq,
        acknowledgmentNumber = 0L,
        flags = flags,
        window = window,
        payload = payload,
        identification = 1,
        ttl = 64,
        tcpHeaderLength = 20,
    )
}
