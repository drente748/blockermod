package com.blockermod.platform.vpn

import com.blockermod.core.DomainMatcher
import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsTypes
import com.blockermod.core.net.Ipv4TcpCodec
import com.blockermod.core.net.Ipv4TcpPacket
import com.blockermod.core.net.Ipv4UdpPacket
import com.blockermod.core.policy.TransportPolicy
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * End-to-end JVM tests for the tunnel's transport policy and per-flow ordering. Android-only bits
 * (VpnService.Builder routes, NetworkCallback) are covered by code review + CI greps and need a real
 * device; see docs/MANUAL_TESTS.md.
 */
class VpnTunnelIntegrationTest {

    private val noDomains = object : DomainMatcher {
        override fun matches(domain: String) = false
    }

    private fun policy(blockAllQuic: Boolean = false) = TransportPolicy(
        isKnownEncryptedResolver = { false },
        dohHosts = noDomains,
        blockAllQuic = blockAllQuic,
    )

    /** Counts forwarded datagrams without any real socket/network I/O. */
    private class CountingUdpRelay : UdpRelay(protectSocket = { false }, writePacket = {}) {
        @Volatile var forwarded = 0
        override fun handle(packet: Ipv4UdpPacket) { forwarded++ }
    }

    /** Waits until [condition] holds or the deadline passes; bounded, no arbitrary sleeps. */
    private fun waitForDispatch(condition: () -> Boolean, timeoutMs: Long = 2000) {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(10)
    }

    @Test
    fun `full tunnel blocks DoQ on UDP 853 for every destination`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val relay = CountingUdpRelay()
        val tunnel = VpnTunnel(
            input, output, responder(), fullTunnel = true,
            udpRelay = relay, transportPolicy = policy(),
        )

        tunnel.start()
        input.offer(TestPackets.ipv4Udp(byteArrayOf(1, 2, 3), destinationPort = 853, destinationAddress = LOCAL))
        waitForDispatch(condition = { tunnel.processedPackets() >= 1 })
        tunnel.stop()

        assertEquals(0, relay.forwarded, "UDP/853 must never reach the relay")
        assertEquals(0, output.size())
    }

    @Test
    fun `full tunnel allows ordinary UDP 443 by default`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val relay = CountingUdpRelay()
        val tunnel = VpnTunnel(
            input, output, responder(), fullTunnel = true,
            udpRelay = relay, transportPolicy = policy(),
        )

        tunnel.start()
        input.offer(TestPackets.ipv4Udp(byteArrayOf(1, 2, 3), destinationPort = 443, destinationAddress = LOCAL))
        // Wait for the observable outcome, not the counter incremented at the top of handle():
        // processedPackets can be set before the worker reaches udpRelay.handle().
        waitForDispatch(condition = { relay.forwarded >= 1 })
        tunnel.stop()

        assertEquals(1, relay.forwarded, "HTTP/3 must keep working unless QUIC block is opted in")
    }

    @Test
    fun `full tunnel blocks UDP 443 when QUIC block is enabled`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val relay = CountingUdpRelay()
        val tunnel = VpnTunnel(
            input, output, responder(), fullTunnel = true,
            udpRelay = relay, transportPolicy = policy(blockAllQuic = true),
        )

        tunnel.start()
        input.offer(TestPackets.ipv4Udp(byteArrayOf(1, 2, 3), destinationPort = 443, destinationAddress = LOCAL))
        waitForDispatch(condition = { tunnel.processedPackets() >= 1 })
        tunnel.stop()

        assertEquals(0, relay.forwarded)
    }

    @Test
    fun `ipv6 packets are never parsed or forwarded`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val relay = CountingUdpRelay()
        val tunnel = VpnTunnel(
            input, output, responder(), fullTunnel = true,
            udpRelay = relay, transportPolicy = policy(),
        )
        val ipv6 = ByteArray(40).also { it[0] = 0x60; it[6] = 17 }

        tunnel.start()
        input.offer(ipv6)
        waitForDispatch(condition = { tunnel.processedPackets() >= 1 })
        tunnel.stop()

        assertEquals(0, relay.forwarded)
        assertEquals(0, output.size())
    }

    @Test
    fun `a tcp dns message split across segments stays ordered through the dispatcher`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val answers = ArrayList<ByteArray>()
        val endpoint = DnsTcpEndpoint(
            writePacket = { answers += it },
            resolve = { DnsCodec.buildNxDomain(DnsCodec.parseQuery(it)!!) },
        )
        val tunnel = VpnTunnel(input, output, responder(), dnsTcpEndpoint = endpoint)

        val framed = com.blockermod.core.dns.frameDnsTcp(
            DnsWire.buildQuery(0x51, "ordered.example", DnsTypes.A),
        )
        tunnel.start()
        input.offer(tcp(1L, Ipv4TcpCodec.Flags.SYN))
        framed.forEachIndexed { index, byte ->
            input.offer(tcp(2L + index, Ipv4TcpCodec.Flags.ACK, byteArrayOf(byte)))
        }
        Thread.sleep(600)
        tunnel.stop()

        val dataPackets = answers.mapNotNull { Ipv4TcpCodec.parse(it) }
            .filter { it.flags and Ipv4TcpCodec.Flags.PSH != 0 }
        assertEquals(1, dataPackets.size, "reordered segments must still yield exactly one answer")
        val answer = dataPackets.single().payload
        assertEquals(0x51, ((answer[2].toInt() and 0xFF) shl 8) or (answer[3].toInt() and 0xFF))
    }

    private fun tcp(seq: Long, flags: Int, payload: ByteArray = ByteArray(0)): ByteArray =
        Ipv4TcpCodec.build(
            // build() swaps endpoints (it is a response builder): give it the swapped tuple so the
            // bytes on the wire carry src=10.0.0.1:40000 -> dst=10.0.0.3:53 (a client DNS segment).
            request = Ipv4TcpPacket(
                sourceAddress = 0x0A000003, destinationAddress = 0x0A000001,
                sourcePort = 53, destinationPort = 40_000,
                sequenceNumber = 0L, acknowledgmentNumber = 0L, flags = 0,
                window = 65_535, payload = EMPTY, identification = 1, ttl = 64, tcpHeaderLength = 20,
            ),
            payload = payload, sequenceNumber = seq, acknowledgmentNumber = 0L, flags = flags,
        )

    private fun responder(): DnsResponder = DnsResponder(
        policy = com.blockermod.core.policy.PolicyEngine(
            allowlist = com.blockermod.core.matcher.InMemoryDomainMatcher(emptySet()),
            adultBlocklist = com.blockermod.core.matcher.InMemoryDomainMatcher(emptySet()),
            bypassBlocklist = com.blockermod.core.matcher.InMemoryDomainMatcher(emptySet()),
            unsupportedEngineBlocklist = com.blockermod.core.matcher.InMemoryDomainMatcher(emptySet()),
            safeSearchTable = com.blockermod.core.policy.InMemorySafeSearchTable(emptyMap()),
        ),
        upstream = object : DnsUpstream {
            override fun lookup(host: String, type: Int) =
                DnsWire.Answer(DnsWire.RCODE_NOERROR, emptyList())
        },
        cache = DnsCache(),
    )

    private companion object {
        const val LOCAL: Int = 0x7F000001
        val EMPTY = ByteArray(0)
    }
}
