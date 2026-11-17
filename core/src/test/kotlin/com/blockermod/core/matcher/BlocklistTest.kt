package com.blockermod.core.matcher

import java.io.File
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Verifies the packed blocklist that ships with the application.
 *
 * The list is built from pinned, license-cleared public sources at build time. These tests prove the
 * packed format is read correctly and that real adult domains are blocked by the matcher.
 */
class BlocklistTest {

    @Test
    fun `the blocklist blocks known adult domains`() {
        val matcher = matcher()

        for (domain in BLOCKED_DOMAINS) {
            assertTrue(matcher.matches(domain), domain)
        }
    }

    @Test
    fun `the blocklist covers subdomains of blocked domains`() {
        val matcher = matcher()

        assertTrue(matcher.matches("deep.www.pornhub.com"))
        assertTrue(matcher.matches("de.redtube.com"))
    }

    @Test
    fun `the packed list keeps parents so they block every child`() {
        // The pack step keeps the most comprehensive ancestor and drops covered children
        // (tools/pack.py). Matching is subdomain-aware, so the apex entry must still block the
        // www./m./de. variants that are no longer stored explicitly.
        val matcher = matcher()

        for (parent in PARENT_DOMAINS) {
            assertTrue(matcher.matches(parent), "the parent $parent must be stored in the list")
            assertTrue(matcher.matches("www.$parent"), "the parent must cover www.$parent")
            assertTrue(matcher.matches("m.$parent"), "the parent must cover m.$parent")
        }
    }

    @Test
    fun `the blocklist leaves unrelated domains alone`() {
        val matcher = matcher()

        for (domain in ALLOWED_DOMAINS) {
            assertFalse(matcher.matches(domain), domain)
        }
    }

    @Test
    fun `the blocklist matches a domain whatever its case`() {
        val matcher = matcher()

        assertTrue(matcher.matches("WWW.PORNHUB.COM"))
    }

    private fun matcher(): BinarySearchDomainMatcher =
        BinarySearchDomainMatcher(ByteBuffer.wrap(blocklist().readBytes()))

    private fun blocklist(): File {
        var directory: File? = File(System.getProperty("user.dir"))

        while (directory != null) {
            val candidate = File(directory, BLOCKLIST_PATH)
            if (candidate.isFile) return candidate
            directory = directory.parentFile
        }

        throw AssertionError("the blocklist was not found")
    }

    private companion object {
        const val BLOCKLIST_PATH: String = "app/src/main/assets/blocklist.bin"

        val BLOCKED_DOMAINS = listOf(
            "www.pornhub.com",
            "www.xvideos.com",
            "www.redtube.com",
            "www.camsoda.com",
            "www.youporn.com",
            "www.xhamster.com",
        )

        val PARENT_DOMAINS = listOf(
            "pornhub.com",
            "xvideos.com",
            "redtube.com",
        )

        val ALLOWED_DOMAINS = listOf(
            "example.com",
            "google.com",
            "blockermod.invalid",
        )
    }
}
