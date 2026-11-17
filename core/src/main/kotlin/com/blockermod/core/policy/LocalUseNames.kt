package com.blockermod.core.policy

/**
 * Names reserved for local use (RFC 6761, RFC 6762, RFC 8375 and common LAN suffixes).
 *
 * They resolve to private or loopback addresses by definition, so the policy must never block
 * them and rebinding protection must never reject their answers. Both the [PolicyEngine] and the
 * platform resolver share this one list so the two layers cannot drift.
 *
 * shortcut: the documentation TLDs ".test"/".example"/".invalid" (RFC 6761) are NOT exempted
 * here: they never resolve, so exempting them would only be able to disable a blocklist entry,
 * and their absence keeps test fixtures honest. They are still filtered at pack time
 * (tools/pack.py LOCAL_USE_SUFFIXES) so no list ships them.
 */
object LocalUseNames {

    private val SUFFIXES = listOf(
        "localhost",     // RFC 6761
        "localdomain",   // classic resolver alias
        "local",         // RFC 6762 (mDNS)
        "home.arpa",     // RFC 8375
        "lan",           // common local-network suffix
        "home",          // common local-network suffix
        "internal",      // common local-network suffix
    )

    /**
     * True for [name] itself or any of its ancestors being a local-use name. Single-label
     * hostnames are local-use by definition.
     */
    fun isLocalUseName(name: String): Boolean {
        val host = name.trim().trimEnd('.').lowercase()
        if (host.isEmpty()) return false
        if (!host.contains('.')) return true // single-label hostname
        return SUFFIXES.any { host == it || host.endsWith(".$it") }
    }
}
