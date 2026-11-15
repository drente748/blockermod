package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import com.blockermod.core.net.Ipv4UdpCodec
import com.blockermod.core.matcher.InMemoryDomainMatcher
import com.blockermod.core.policy.InMemorySafeSearchTable
import com.blockermod.core.policy.PolicyEngine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class VpnTunnelTest {

    @Test
    fun `stopping the tunnel returns it to idle and ends the reader`() {
        val input = BlockingInputStream()
        val tunnel = VpnTunnel(input, SignallingOutputStream(), responder())

        tunnel.start()
        assertEquals(TunnelState.Running, tunnel.state)

        tunnel.stop()

        assertTrue(tunnel.awaitStopped(3000))
        assertEquals(TunnelState.Idle, tunnel.state)
    }

    @Test
    fun `a blocked query is answered with a name error`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val tunnel = VpnTunnel(input, output, responder(adultBlocklist = setOf("adult.example")))

        tunnel.start()
        input.offer(TestPackets.ipv4Udp(DnsWire.buildQuery(0x7777, "adult.example", DnsTypes.A)))
        assertTrue(output.awaitWritten(3000))
        tunnel.stop()

        val answer = Ipv4UdpCodec.parseIpv4Udp(output.toByteArray())
        assertNotNull(answer)
        assertEquals(53, answer.sourcePort)
        assertEquals(3, readU16(answer.payload, 2) and 0x0F)
    }

    @Test
    fun `a packet addressed to another port is dropped`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val tunnel = VpnTunnel(input, output, responder())

        tunnel.start()
        input.offer(TestPackets.ipv4Udp(byteArrayOf(1, 2, 3), destinationPort = 1234))
        Thread.sleep(200)
        tunnel.stop()

        assertEquals(0, output.size())
    }

    @Test
    fun `tcp packets to the dns port are counted and dropped`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val tunnel = VpnTunnel(input, output, responder())

        tunnel.start()
        input.offer(TestPackets.ipv4Tcp())
        Thread.sleep(200)
        tunnel.stop()

        assertEquals(1, tunnel.tcpPackets())
        assertEquals(0, output.size())
    }

    @Test
    fun `the tunnel answers several queries`() {
        val input = BlockingInputStream()
        val output = SignallingOutputStream()
        val tunnel = VpnTunnel(input, output, responder(adultBlocklist = setOf("adult.example")))

        tunnel.start()
        input.offer(TestPackets.ipv4Udp(DnsWire.buildQuery(1, "adult.example", DnsTypes.A)))
        input.offer(TestPackets.ipv4Udp(DnsWire.buildQuery(2, "adult.example", DnsTypes.A)))
        Thread.sleep(300)
        tunnel.stop()

        assertEquals(2, tunnel.answeredPackets())
    }

    private fun responder(adultBlocklist: Set<String> = emptySet()): DnsResponder = DnsResponder(
        policy = PolicyEngine(
            allowlist = InMemoryDomainMatcher(emptySet()),
            adultBlocklist = InMemoryDomainMatcher(adultBlocklist),
            bypassBlocklist = InMemoryDomainMatcher(emptySet()),
            unsupportedEngineBlocklist = InMemoryDomainMatcher(emptySet()),
            safeSearchTable = InMemorySafeSearchTable(emptyMap()),
        ),
        upstream = EmptyUpstream,
    )

    private object EmptyUpstream : DnsUpstream {
        override fun lookup(host: String, type: Int) = emptyList<DnsRecord>()
    }

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
}
