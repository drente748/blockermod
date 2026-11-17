package com.blockermod.core.policy

import com.blockermod.core.DomainMatcher

/** Transport of a packet inspected by the engine. */
enum class PacketTransport {
    UDP_DNS_53, TCP_DNS_53, TCP_DOT_853, UDP_DOQ_853,
    TCP_DOH_443, UDP_QUIC_443, OTHER_TCP, OTHER_UDP,
}

/** Result of the transport policy decision. */
enum class TransportAction {
    ALLOW, BLOCK_ENCRYPTED_DNS, BLOCK_QUIC,
}

/**
 * Single place that decides what to do with encrypted DNS transports.
 *
 * Policy, not packet parsing: the caller classifies the packet into [PacketTransport] and supplies
 * the known resolver IP set and the DoH domain matcher. Keeping this in :core makes every branch
 * unit-testable without Android or a live tunnel.
 */
class TransportPolicy(
    private val isKnownEncryptedResolver: (String) -> Boolean,
    private val dohHosts: DomainMatcher,
    private val blockAllQuic: Boolean = false,
) {

    fun decide(
        transport: PacketTransport,
        destinationAddress: String,
        serverName: String? = null,
        echDetected: Boolean = false,
    ): TransportAction = when (transport) {
        PacketTransport.TCP_DNS_53, PacketTransport.UDP_DNS_53,
        PacketTransport.OTHER_TCP, PacketTransport.OTHER_UDP -> TransportAction.ALLOW

        // DoT and DoQ on the dedicated port are encrypted DNS by definition (RFC 7858 / RFC 9250).
        PacketTransport.TCP_DOT_853, PacketTransport.UDP_DOQ_853 -> TransportAction.BLOCK_ENCRYPTED_DNS

        PacketTransport.TCP_DOH_443 -> when {
            isKnownEncryptedResolver(destinationAddress) -> TransportAction.BLOCK_ENCRYPTED_DNS
            serverName != null && dohHosts.matches(serverName) -> TransportAction.BLOCK_ENCRYPTED_DNS
            // ECH hides the name: never claim this is blocked, but do not break all TLS either.
            echDetected -> TransportAction.ALLOW
            else -> TransportAction.ALLOW
        }

        PacketTransport.UDP_QUIC_443 -> when {
            isKnownEncryptedResolver(destinationAddress) || blockAllQuic -> TransportAction.BLOCK_QUIC
            else -> TransportAction.ALLOW
        }
    }
}
