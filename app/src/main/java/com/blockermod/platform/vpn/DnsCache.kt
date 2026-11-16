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

    /** Short-lived negative answers (NXDOMAIN/NODATA), keyed the same way as positive entries. */
    private val negative = object : LinkedHashMap<String, Long>(INITIAL_CAPACITY, LOAD_FACTOR, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean =
            size > maxEntries
    }

    /**
     * Remembers that a name had no answer, so repeated lookups avoid another upstream round trip.
     */
    @Synchronized
    fun rememberNegative(
        key: String,
        ttlSeconds: Long,
        nowMillis: Long = System.currentTimeMillis(),
    ) {
        negative[key] = nowMillis + effectiveTtlSeconds(ttlSeconds) * 1000L
    }

    /**
     * True when [key] is known to have no answer and the short TTL has not expired.
     */
    @Synchronized
    fun isNegative(key: String, nowMillis: Long = System.currentTimeMillis()): Boolean {
        val until = negative[key] ?: return false
        if (until <= nowMillis) {
            negative.remove(key)
            return false
        }
        return true
    }

    /**
     * Returns the cached records for the key, or null when the entry is missing or expired.
     */
    @Synchronized
    fun get(key: String, nowMillis: Long = System.currentTimeMillis()): List<DnsRecord>? {
        val entry = entries[key] ?: return null
        if (entry.expiresAtMillis <= nowMillis) {
            entries.remove(key)
            return null
        }
        return entry.records
    }

    /**
     * Like [get], but returns the records with their remaining TTL so cached answers do not keep
     * advertising a TTL that has already elapsed at the client.
     */
    @Synchronized
    fun getFresh(key: String, nowMillis: Long = System.currentTimeMillis()): List<DnsRecord>? {
        val entry = entries[key] ?: return null
        if (entry.expiresAtMillis <= nowMillis) {
            entries.remove(key)
            return null
        }
        val remaining = maxOf(1L, (entry.expiresAtMillis - nowMillis) / 1000L)
        return entry.records.map { record ->
            DnsRecord(
                record.name,
                record.type,
                record.klass,
                minOf(record.ttlSeconds, remaining),
                record.data,
            )
        }
    }

    /**
     * Stores the records under the key with a time to live clamped to the configured range.
     */
    @Synchronized
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
    @Synchronized
    fun size(): Int = entries.size

    /**
     * Drops every entry.
     */
    @Synchronized
    fun clear() {
        entries.clear()
        negative.clear()
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
