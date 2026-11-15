package com.blockermod.core.matcher

import java.io.File
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Verifies the placeholder blocklist that ships with the application.
 *
 * The placeholder is a synthetic fixture: it proves that the packed format written by the build
 * script is read by the matcher without any parsing step.
 */
class BlocklistPlaceholderTest {

    @Test
    fun `the placeholder blocks the known domains`() {
        val matcher = matcher()

        for (domain in KNOWN_DOMAINS) {
            assertTrue(matcher.matches(domain), domain)
        }
    }

    @Test
    fun `the placeholder leaves the other domains alone`() {
        val matcher = matcher()

        for (domain in ALLOWED_DOMAINS) {
            assertFalse(matcher.matches(domain), domain)
        }
    }

    @Test
    fun `the placeholder covers the subdomains of its entries`() {
        val matcher = matcher()

        assertTrue(matcher.matches("deep.ads.example.com"))
    }

    @Test
    fun `the placeholder matches a domain whatever its case`() {
        val matcher = matcher()

        assertTrue(matcher.matches("ADS.Example.COM"))
    }

    private fun matcher(): BinarySearchDomainMatcher =
        BinarySearchDomainMatcher(ByteBuffer.wrap(blocklist().readBytes()))

    private fun blocklist(): File {
        var directory: File? = File(System.getProperty("user.dir"))

        while (directory != null) {
            val candidate = File(directory, PLACEHOLDER_PATH)
            if (candidate.isFile) return candidate
            directory = directory.parentFile
        }

        throw AssertionError("the placeholder blocklist was not found")
    }

    private companion object {
        const val PLACEHOLDER_PATH: String = "app/src/main/assets/blocklist.bin"

        val KNOWN_DOMAINS = listOf(
            "ads.example.com",
            "tracker.example.net",
            "metrics.example.org",
            "pixel-001.example.co.uk",
            "xn--bcher-kva.example",
        )

        val ALLOWED_DOMAINS = listOf(
            "example.com",
            "safe.example.com",
            "google.com",
        )
    }
}
