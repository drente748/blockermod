package com.blockermod.platform.vpn

import com.blockermod.core.BlockReason
import com.blockermod.core.DomainMatcher
import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.policy.PolicyEngine

/**
 * Thin adapter around the [LocalDnsResolver].
 *
 * The resolver owns all DNS logic (policy, cache, CNAME chains, SafeSearch, rebinding protection);
 * this class only parses the wire payload for UDP and keeps the debug decision trail.
 */
internal class DnsResponder(
    policy: PolicyEngine,
    upstream: DnsUpstream,
    cache: DnsCache,
    private val logOnly: Boolean = false,
    onBlocked: (BlockReason) -> Unit = {},
) {

    private val resolver = LocalDnsResolver(policy, upstream, cache, onBlocked, bypassPolicy = logOnly)

    /** Records of the decisions taken while the debug mode is on, without any formatting. */
    val decisions: DecisionTrail = DecisionTrail()

    /** Answers a raw UDP DNS payload, or null when the payload is not a query. */
    fun respond(payload: ByteArray): ByteArray? {
        val query = DnsCodec.parseQuery(payload) ?: return null
        // RFC 6891 6.2.3: an advertised payload below 512 is treated as 512. Answers larger than
        // the limit go out with TC=1 and the client retries over TCP (B2).
        val udpPayloadSize = query.edns?.payloadSize?.coerceIn(MIN_CLIENT_PAYLOAD, 65535) ?: MIN_CLIENT_PAYLOAD
        val response = resolver.resolve(payload, udpPayloadSize)
        if (logOnly) decisions.record(com.blockermod.core.BlockingResult.Allowed)
        return response
    }

    /** Resolves a raw DNS message (already unframed); returns a raw DNS response or null. */
    fun resolveDnsMessage(message: ByteArray): ByteArray? = resolver.resolve(message)

    /** The bypass list, used by the full-tunnel relay to stop DoH by TLS SNI. */
    fun bypassMatcher(): DomainMatcher = resolver.bypassMatcher()

    /** Drops cached answers; called when the upstream network changes. */
    fun clearCache() = resolver.clearCache()

    private companion object {
        /** RFC 6891 6.2.3: payloads below 512 bytes are treated as 512. */
        const val MIN_CLIENT_PAYLOAD: Int = 512
    }
}
