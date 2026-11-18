package com.blockermod.platform.vpn

import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** One parse per query and O(1) lookup; all 26 shipped literals classify correctly (C3). */
class StrictResolverSetTest {

    @Test
    fun `every shipped resolver is classified with a single parse per query`() {
        val entries = asset().readLines().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
        assertEquals(26, entries.size)
        val parses = AtomicInteger(0)
        val counting: (String) -> Int? = { value ->
            parses.incrementAndGet()
            NumericAddresses.parse(value)?.address?.fold(0) { acc, b -> (acc shl 8) or (b.toInt() and 0xFF) }
        }
        val set = StrictResolverSet(entries, counting)
        assertEquals(26, parses.get(), "the 26 literals are parsed once at construction")
        assertEquals(26, set.values.size, "the literals are unique IPv4 values")

        for (address in entries) assertTrue(set.contains(address), "missing $address")
        assertEquals(26 + 26, parses.get(), "each query parses its address exactly once")

        for (bad in listOf("dns.google", "localhost", "999.1.1.1", "1.1.1.1:53")) {
            assertFalse(set.contains(bad), bad)
        }
    }

    private fun asset(): File {
        var directory: File? = File(System.getProperty("user.dir"))
        while (directory != null) {
            val candidate = File(directory, "app/src/main/assets/strict-resolvers.txt")
            if (candidate.isFile) return candidate
            directory = directory.parentFile
        }
        throw AssertionError("the strict resolver asset was not found")
    }
}
