package com.blockermod.platform.vpn

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The shipped strict-resolver asset must carry every known encrypted-DNS endpoint (B10). */
class StrictResolversAssetTest {

    @Test
    fun `the asset holds 26 distinct numeric resolver addresses`() {
        val entries = asset().readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }

        assertEquals(26, entries.size)
        assertEquals(entries.size, entries.toSet().size, "no duplicate addresses")
        assertTrue(entries.all { NumericAddresses.parse(it) != null }, "addresses only, no hostnames")
    }

    @Test
    fun `the additional provider pools are covered`() {
        val entries = asset().readLines().map { it.trim() }.toSet()

        for (address in listOf(
            "1.1.1.2", "9.9.9.10", "94.140.14.15", "208.67.222.123",
            "185.228.168.168", "45.90.30.0", "76.76.2.0",
        )) {
            assertTrue(entries.contains(address), "missing strict resolver $address")
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
