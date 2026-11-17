package com.blockermod.core.policy

import com.blockermod.core.DomainMatcher
import kotlin.test.Test
import kotlin.test.assertEquals

class TransportPolicyTest {

    private val matcher = object : DomainMatcher {
        override fun matches(domain: String) = domain == "dns.google"
    }
    private val policy = TransportPolicy(
        isKnownEncryptedResolver = { it == "94.140.14.14" },
        dohHosts = matcher,
    )

    @Test
    fun `dot and doq dedicated ports are always blocked`() {
        assertEquals(TransportAction.BLOCK_ENCRYPTED_DNS, policy.decide(PacketTransport.TCP_DOT_853, "1.2.3.4"))
        assertEquals(TransportAction.BLOCK_ENCRYPTED_DNS, policy.decide(PacketTransport.UDP_DOQ_853, "1.2.3.4"))
    }

    @Test
    fun `known resolver on 443 is blocked for both tcp and udp`() {
        assertEquals(
            TransportAction.BLOCK_ENCRYPTED_DNS,
            policy.decide(PacketTransport.TCP_DOH_443, "94.140.14.14"),
        )
        assertEquals(
            TransportAction.BLOCK_QUIC,
            policy.decide(PacketTransport.UDP_QUIC_443, "94.140.14.14"),
        )
    }

    @Test
    fun `doh domain from sni is blocked`() {
        assertEquals(
            TransportAction.BLOCK_ENCRYPTED_DNS,
            policy.decide(PacketTransport.TCP_DOH_443, "1.2.3.4", "dns.google"),
        )
    }

    @Test
    fun `plain dns and ordinary traffic are allowed`() {
        assertEquals(TransportAction.ALLOW, policy.decide(PacketTransport.UDP_DNS_53, "94.140.14.14"))
        assertEquals(TransportAction.ALLOW, policy.decide(PacketTransport.TCP_DNS_53, "94.140.14.14"))
        assertEquals(TransportAction.ALLOW, policy.decide(PacketTransport.OTHER_TCP, "94.140.14.14"))
    }

    @Test
    fun `quic block is opt in`() {
        assertEquals(TransportAction.ALLOW, policy.decide(PacketTransport.UDP_QUIC_443, "1.2.3.4"))
        val strict = TransportPolicy({ false }, matcher, blockAllQuic = true)
        assertEquals(TransportAction.BLOCK_QUIC, strict.decide(PacketTransport.UDP_QUIC_443, "1.2.3.4"))
    }

    @Test
    fun `ech does not justify blocking all tls`() {
        assertEquals(
            TransportAction.ALLOW,
            policy.decide(PacketTransport.TCP_DOH_443, "1.2.3.4", echDetected = true),
        )
    }
}
