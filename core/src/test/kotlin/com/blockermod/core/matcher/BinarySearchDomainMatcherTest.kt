package com.blockermod.core.matcher

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BinarySearchDomainMatcherTest {

    @Test
    fun `matches an exact domain`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("ads.example.com"))
    }

    @Test
    fun `matches a subdomain`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("tracker.ads.example.com"))
    }

    @Test
    fun `matches a deep subdomain`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("a.b.c.ads.example.com"))
    }

    @Test
    fun `does not match a partial label`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertFalse(matcher.matches("notads.example.com"))
    }

    @Test
    fun `does not match a sibling domain`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertFalse(matcher.matches("ads.example.net"))
        assertFalse(matcher.matches("example.com"))
    }

    @Test
    fun `matches an internationalized domain after punycode conversion`() {
        val matcher = matcher(listOf("xn--bcher-kva.example"))

        assertTrue(matcher.matches("bücher.example"))
    }

    @Test
    fun `matches a domain with a trailing dot`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("ads.example.com."))
    }

    @Test
    fun `matches regardless of the case`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("ADS.Example.COM"))
    }

    @Test
    fun `matches a top level domain entry`() {
        val matcher = matcher(listOf("com"))

        assertTrue(matcher.matches("example.com"))
    }

    @Test
    fun `returns false for an empty buffer`() {
        val matcher = BinarySearchDomainMatcher(ByteBuffer.allocate(0))

        assertFalse(matcher.matches("example.com"))
    }

    @Test
    fun `does not mutate the position of the source buffer`() {
        val buffer = pack(listOf("ads.example.com"))
        val matcher = BinarySearchDomainMatcher(buffer)

        matcher.matches("ads.example.com")

        assertEquals(0, buffer.position())
    }

    @Test
    fun `finds every entry of a multi entry list`() {
        val matcher = matcher(listOf("ads.example.com", "tracker.net", "bad.example.org"))

        assertTrue(matcher.matches("ads.example.com"))
        assertTrue(matcher.matches("tracker.net"))
        assertTrue(matcher.matches("bad.example.org"))
        assertTrue(matcher.matches("x.tracker.net"))
        assertFalse(matcher.matches("safe.example.com"))
    }

    @Test
    fun `rejects an unsorted buffer`() {
        val buffer = pack(listOf("ads.example.com", "aaa.example.com"), sort = false)

        assertFailsWith<IllegalArgumentException> { BinarySearchDomainMatcher(buffer) }
    }

    @Test
    fun `rejects a truncated buffer`() {
        val buffer = pack(listOf("ads.example.com"))
        val truncated = ByteBuffer.wrap(buffer.array().copyOfRange(0, buffer.array().size - 3))

        assertFailsWith<IllegalArgumentException> { BinarySearchDomainMatcher(truncated) }
    }

    @Test
    fun `returns false for an empty domain`() {
        val matcher = matcher(listOf("ads.example.com"))

        assertFalse(matcher.matches(""))
        assertFalse(matcher.matches("."))
    }

    private fun matcher(domains: List<String>): BinarySearchDomainMatcher =
        BinarySearchDomainMatcher(pack(domains))

    private fun pack(domains: List<String>, sort: Boolean = true): ByteBuffer {
        val entries = domains.map { entryBytes(it) }
        val ordered = if (sort) entries.sortedWith { left, right -> compareBytes(left, right) } else entries
        val out = ByteArrayOutputStream()

        for (entry in ordered) {
            out.write((entry.size ushr 8) and 0xFF)
            out.write(entry.size and 0xFF)
            out.write(entry)
        }

        return ByteBuffer.wrap(out.toByteArray())
    }

    private fun entryBytes(domain: String): ByteArray {
        val labels = domain.trimEnd('.').lowercase().split('.').filter { it.isNotEmpty() }.reversed()
        return labels.joinToString("\u0000") { it }.toByteArray(Charsets.US_ASCII)
    }

    private fun compareBytes(left: ByteArray, right: ByteArray): Int {
        val shared = minOf(left.size, right.size)
        for (index in 0 until shared) {
            val a = left[index].toInt() and 0xFF
            val b = right[index].toInt() and 0xFF
            if (a != b) return if (a < b) -1 else 1
        }
        return left.size.compareTo(right.size)
    }
}
