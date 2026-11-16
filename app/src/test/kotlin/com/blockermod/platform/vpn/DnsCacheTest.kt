package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsCacheTest {

    @Test
    fun `stores and returns the records`() {
        val cache = DnsCache()
        val records = listOf(DnsRecord("a.example", DnsTypes.A, 1, 60, byteArrayOf(10, 0, 0, 1)))

        cache.put("a.example/1", records, 60)
        val cached = cache.get("a.example/1")

        assertEquals(1, cached?.size)
        assertEquals(records[0].name, cached?.get(0)?.name)
    }

    @Test
    fun `returns null for an unknown key`() {
        assertNull(DnsCache().get("missing/1"))
    }

    @Test
    fun `clamps the time to live to the minimum`() {
        assertEquals(DnsCache.MIN_TTL_SECONDS, DnsCache().effectiveTtlSeconds(1))
    }

    @Test
    fun `clamps the time to live to the maximum`() {
        assertEquals(DnsCache.MAX_TTL_SECONDS, DnsCache().effectiveTtlSeconds(100_000))
    }

    @Test
    fun `keeps a value inside the range untouched`() {
        assertEquals(120L, DnsCache().effectiveTtlSeconds(120))
    }

    @Test
    fun `drops an expired entry`() {
        val cache = DnsCache()
        cache.put("a.example/1", listOf(DnsRecord("a.example", DnsTypes.A, 1, 60, byteArrayOf(1))), 60, nowMillis = 0)

        assertNull(cache.get("a.example/1", nowMillis = 120_000))
    }

    @Test
    fun `evicts the least recently used entry when the limit is reached`() {
        val cache = DnsCache()
        val records = listOf(DnsRecord("a.example", DnsTypes.A, 1, 60, byteArrayOf(1)))

        for (index in 0 until DnsCache.MAX_ENTRIES + 1) {
            cache.put("host-$index/1", records, 60)
        }

        assertEquals(DnsCache.MAX_ENTRIES, cache.size())
        assertNull(cache.get("host-0/1"))
        assertTrue(cache.get("host-${DnsCache.MAX_ENTRIES}/1") != null)
    }

    @Test
    fun `ignores an empty record set`() {
        val cache = DnsCache()

        cache.put("a.example/1", emptyList(), 60)

        assertEquals(0, cache.size())
    }

    @Test
    fun `negative answers are remembered then expire`() {
        val cache = DnsCache()
        cache.rememberNegative("missing.example/1", 60, nowMillis = 0)

        assertTrue(cache.isNegative("missing.example/1", nowMillis = 59_000))
        assertFalse(cache.isNegative("missing.example/1", nowMillis = 61_000))
    }

    @Test
    fun `clearing drops negative answers too`() {
        val cache = DnsCache()
        cache.rememberNegative("missing.example/1", 60)
        assertTrue(cache.isNegative("missing.example/1"))

        cache.clear()

        assertFalse(cache.isNegative("missing.example/1"))
    }
}
