package com.blockermod.platform.vpn

import com.blockermod.core.BlockReason
import com.blockermod.core.BlockingResult
import com.blockermod.core.matcher.BinarySearchDomainMatcher
import com.blockermod.core.policy.InMemorySafeSearchTable
import com.blockermod.core.policy.PolicyEngine
import java.io.File
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * End-to-end check of the rule sources shipped in the APK: the packed lists are loaded from disk and
 * driven through the real [PolicyEngine], so a broken asset or a mismatched matcher format fails
 * the build instead of shipping silently.
 */
class PackedPolicyIntegrationTest {

    private val engine: PolicyEngine by lazy {
        PolicyEngine(
            allowlist = com.blockermod.core.matcher.InMemoryDomainMatcher(readTextAsset("allowlist.txt").toSet()),
            adultBlocklist = packed("blocklist.bin"),
            bypassBlocklist = packed("bypass.bin"),
            unsupportedEngineBlocklist = packed("unsupported.bin"),
            safeSearchTable = InMemorySafeSearchTable(mapOf("www.google.com" to "forcesafesearch.google.com")),
        )
    }

    @Test
    fun `shipped blocklist blocks real adult domains`() {
        for (domain in listOf("www.pornhub.com", "www.xvideos.com", "www.redtube.com")) {
            val result = engine.evaluate(domain)
            assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_ADULT), result, domain)
        }
    }

    @Test
    fun `shipped bypass list blocks encrypted DNS hosts`() {
        val domain = packedDomains("bypass.bin").first { it.startsWith("dns.") }

        assertEquals(
            BlockingResult.Blocked(BlockReason.BLOCKLIST_BYPASS),
            engine.evaluate(domain),
            domain,
        )
    }

    @Test
    fun `shipped unsupported list blocks search engines without safesearch`() {
        val result = engine.evaluate("baidu.com")

        assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_UNSUPPORTED_ENGINE), result)
    }

    @Test
    fun `allowlist and safesearch still work with real lists`() {
        assertIs<BlockingResult.Allowed>(engine.evaluate("example.org"))
        assertEquals(
            BlockingResult.Rewrite("forcesafesearch.google.com", "www.google.com"),
            engine.evaluate("www.google.com"),
        )
    }

    private fun packed(name: String): BinarySearchDomainMatcher =
        BinarySearchDomainMatcher(ByteBuffer.wrap(File(assetDir(), name).readBytes()))

    private fun packedDomains(name: String): List<String> {
        val bytes = File(assetDir(), name).readBytes()
        var position = 0
        val result = ArrayList<String>()
        while (position < bytes.size) {
            val length = ((bytes[position].toInt() and 0xFF) shl 8) or (bytes[position + 1].toInt() and 0xFF)
            val reversed = bytes.copyOfRange(position + 2, position + 2 + length)
            result += reversed.toString(Charsets.US_ASCII).split('\u0000').reversed().joinToString(".")
            position += 2 + length
        }
        return result
    }

    private fun readTextAsset(name: String): List<String> =
        File(assetDir(), name).readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }

    private fun assetDir(): File {
        var directory: File? = File(System.getProperty("user.dir"))
        while (directory != null) {
            val candidate = File(directory, "app/src/main/assets")
            if (candidate.isDirectory) return candidate
            directory = directory.parentFile
        }
        throw AssertionError("assets directory not found")
    }
}
