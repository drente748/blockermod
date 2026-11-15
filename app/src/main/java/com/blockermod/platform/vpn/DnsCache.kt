package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsRecord

/**
 * Bounded cache of upstream answers.
 *
 * The cache holds at most [maxEntries] records sets, evicts the least recently used entry when
 * the limit is reached, and clamps every time to live between [minTtlSeconds] and
 * [maxTtlSeconds]. Only answers that the engine allowed are stored: blocked domains are never
 * resolved and therefore never cached.
 */
internal class DnsCache(
    private val maxEntries: Int = MAX_ENTRIES,
    private val minTtlSeconds: Long = MIN_TTL_SECONDS,
    private val maxTtlSeconds: Long = MAX_TTL_SECONDS,
) {

    private class Entry(val records: List<DnsRecord>, val expiresAtMillis: Long)

    private val entries = object : LinkedHashMap<String, Entry>(INITIAL_CAPACITY, LOAD_FACTOR, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean =
            size > maxEntries
    }

    /**
     * Returns the cached records for the key, or null when the entry is missing or expired.
     */
    fun get(key: String, nowMillis: Long = System.currentTimeMillis()): List<DnsRecord>? {
        val entry = entries[key] ?: return null
        if (entry.expiresAtMillis <= nowMillis) {
            entries.remove(key)
            return null
        }
        return entry.records
    }

    /**
     * Stores the records under the key with a time to live clamped to the configured range.
     */
    fun put(
        key: String,
        records: List<DnsRecord>,
        ttlSeconds: Long,
        nowMillis: Long = System.currentTimeMillis(),
    ) {
        if (records.isEmpty()) return
        val ttl = effectiveTtlSeconds(ttlSeconds)
        entries[key] = Entry(records, nowMillis + ttl * 1000L)
    }

    /**
     * Number of entries currently held.
     */
    fun size(): Int = entries.size

    /**
     * Drops every entry.
     */
    fun clear() {
        entries.clear()
    }

    /**
     * Clamps a time to live to the configured range.
     */
    fun effectiveTtlSeconds(ttlSeconds: Long): Long = ttlSeconds.coerceIn(minTtlSeconds, maxTtlSeconds)

    companion object {
        /** Maximum number of cached entries. */
        const val MAX_ENTRIES: Int = 512

        /** Lower bound of the cached time to live, in seconds. */
        const val MIN_TTL_SECONDS: Long = 30L

        /** Upper bound of the cached time to live, in seconds. */
        const val MAX_TTL_SECONDS: Long = 300L

        private const val INITIAL_CAPACITY: Int = 16
        private const val LOAD_FACTOR: Float = 0.75f
    }
}
