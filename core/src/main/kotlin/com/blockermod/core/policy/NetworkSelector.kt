package com.blockermod.core.policy

/**
 * Snapshot of one network as reported by Android's NetworkCallback. No Android types leak here.
 */
data class NetworkCandidate(
    val id: String,
    val hasInternet: Boolean,
    val isVpn: Boolean,
    val isValidated: Boolean,
    val isLosing: Boolean = false,
    val dnsServers: List<String> = emptyList(),
    val isPrivateDnsActive: Boolean = false,
)

/**
 * Deterministic network selection policy for upstream DNS.
 *
 * Rules, in order:
 * 1. ignore VPNs, networks without INTERNET and networks that are losing;
 * 2. prefer validated networks over unvalidated ones;
 * 3. keep the currently selected network if it is still eligible (avoid flapping);
 * 4. otherwise choose the smallest id for determinism.
 *
 * An empty DNS list does NOT disqualify a network: Android may report link properties slightly later.
 * It does mean upstream lookups must fail closed until DNS arrives.
 */
class NetworkSelector {

    /** Returns the selected candidate, or null when no eligible network exists. */
    fun select(candidates: Collection<NetworkCandidate>, currentId: String? = null): NetworkCandidate? {
        val eligible = candidates.filter { it.hasInternet && !it.isVpn && !it.isLosing }
        if (eligible.isEmpty()) return null
        val best = eligible.filter { it.isValidated }.ifEmpty { eligible }
        return best.firstOrNull { it.id == currentId }
            ?: best.minWithOrNull(compareBy<NetworkCandidate> { it.isValidated }.reversed().thenBy { it.id })
    }
}
