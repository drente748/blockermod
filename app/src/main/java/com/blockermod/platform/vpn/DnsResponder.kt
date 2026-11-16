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
        val response = resolver.resolve(payload)
        if (logOnly) decisions.record(com.blockermod.core.BlockingResult.Allowed)
        return response
    }

    /** Fully resolves a DNS-over-TCP message; returns a framed response, or null when malformed. */
    fun resolveTcp(framed: ByteArray): ByteArray? = resolver.resolveFramed(framed)

    /** The bypass list, used by the full-tunnel relay to stop DoH by TLS SNI. */
    fun bypassMatcher(): DomainMatcher = resolver.bypassMatcher()

    /** Drops cached answers; called when the upstream network changes. */
    fun clearCache() = resolver.clearCache()
}
