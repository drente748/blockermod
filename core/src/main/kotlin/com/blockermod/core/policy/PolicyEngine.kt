package com.blockermod.core.policy

import com.blockermod.core.BlockReason
import com.blockermod.core.BlockingResult
import com.blockermod.core.DomainMatcher
import com.blockermod.core.lockout.LockoutPolicy
import com.blockermod.core.lockout.NoOpLockoutPolicy
import java.util.Locale

/**
 * Pure decision engine of the blocker.
 *
 * The engine holds no state and performs no input or output: every decision is derived from the
 * rule sets it was built with. The rules are always evaluated in the same order:
 *
 * 1. the lockout policy, which blocks everything while the user is locked out;
 * 2. the canary domain, which exposes applications that bypass the DNS filter;
 * 3. the safe search table, which rewrites the query to a safe search canonical name;
 * 4. the allowlist, which overrides the blocklists only;
 * 5. the adult content blocklist;
 * 6. the bypass attempt blocklist;
 * 7. the blocklist of unsupported engines;
 * 8. allow.
 *
 * @property allowlist domains that are always allowed, even when a blocklist covers them.
 * @property adultBlocklist domains with adult content.
 * @property bypassBlocklist domains used to bypass the filter.
 * @property unsupportedEngineBlocklist domains served by engines the blocker cannot support.
 * @property safeSearchTable table mapping a service host to its safe search canonical name.
 * @property lockoutPolicy decides whether the user is currently locked out.
 */
class PolicyEngine(
    private val allowlist: DomainMatcher,
    private val adultBlocklist: DomainMatcher,
    private val bypassBlocklist: DomainMatcher,
    private val unsupportedEngineBlocklist: DomainMatcher,
    private val safeSearchTable: SafeSearchTable,
    private val lockoutPolicy: LockoutPolicy = NoOpLockoutPolicy(),
) {

    init {
        // Fail-safe: a rule source that cannot answer did not load correctly, so the engine must
        // not exist. The caller never gets the chance to start it.
        probe(allowlist)
        probe(adultBlocklist)
        probe(bypassBlocklist)
        probe(unsupportedEngineBlocklist)
        safeSearchTable.lookup(PROBE_DOMAIN)
    }

    /**
     * Evaluates a domain and returns the decision to apply.
     *
     * The method never throws: odd inputs simply match no rule and are allowed.
     *
     * @param domain domain to evaluate.
     * @return the decision for the domain.
     */
    fun evaluate(domain: String): BlockingResult {
        val normalized = normalize(domain)

        if (lockoutPolicy.isLocked()) {
            return BlockingResult.Blocked(BlockReason.USER_PAUSED)
        }

        if (normalized == CANARY_DOMAIN) {
            return BlockingResult.Blocked(BlockReason.CANARY)
        }

        val safeSearchTarget = safeSearchTable.lookup(normalized)
        if (safeSearchTarget != null) {
            return BlockingResult.Rewrite(safeSearchTarget, normalized)
        }

        if (allowlist.matches(normalized)) {
            return BlockingResult.Allowed
        }

        if (adultBlocklist.matches(normalized)) {
            return BlockingResult.Blocked(BlockReason.BLOCKLIST_ADULT)
        }

        if (bypassBlocklist.matches(normalized)) {
            return BlockingResult.Blocked(BlockReason.BLOCKLIST_BYPASS)
        }

        if (unsupportedEngineBlocklist.matches(normalized)) {
            return BlockingResult.Blocked(BlockReason.BLOCKLIST_UNSUPPORTED_ENGINE)
        }

        return BlockingResult.Allowed
    }

    /** The bypass-attempt matcher, exposed for SNI-based DoH detection in the platform layer. */
    fun bypassMatcher(): DomainMatcher = bypassBlocklist

    private fun probe(source: DomainMatcher) {
        source.matches(PROBE_DOMAIN)
    }

    private fun normalize(domain: String): String {
        val trimmed = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        return trimmed
    }

    private companion object {
        /** Domain used to check that a rule source is able to answer. */
        private const val PROBE_DOMAIN: String = "blockermod-policy-probe.invalid"

        /** Domain that exposes applications bypassing the DNS filter. */
        private const val CANARY_DOMAIN: String = "use-application-dns.net"
    }
}
