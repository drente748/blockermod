package com.blockermod.platform.vpn

/**
 * Parses the strict-resolver literals once at construction, then classifies an incoming address
 * with a single parse and an O(1) set lookup (C3).
 *
 * The parser is injected so the per-packet parsing cost can be asserted in a JVM test; production
 * passes [parseLiteral] which never resolves a hostname.
 */
internal class StrictResolverSet(addresses: Collection<String>, private val parse: (String) -> Int?) {

    val values: Set<Int> = addresses.mapNotNull(parse).toSet()

    fun contains(address: String): Boolean {
        val value = parse(address) ?: return false
        return values.contains(value)
    }
}
