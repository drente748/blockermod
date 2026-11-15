package com.blockermod.core.policy

/**
 * Table that maps a service host to the canonical name enforcing safe search.
 *
 * Lookups are exact host matches: a table entry for `www.google.com` never applies to
 * `mail.google.com` nor to any subdomain of it.
 */
interface SafeSearchTable {

    /**
     * Returns the safe search target for the given host.
     *
     * @param domain host to look up, already normalized by the caller.
     * @return the target canonical name, or null when the host is not covered by the table.
     */
    fun lookup(domain: String): String?
}

/**
 * Safe search table backed by an in memory map.
 *
 * Useful for tests and for small tables that are not worth packing.
 */
class InMemorySafeSearchTable(private val entries: Map<String, String>) : SafeSearchTable {

    /**
     * Returns the safe search target registered for the exact host, or null.
     */
    override fun lookup(domain: String): String? = entries[domain]
}
