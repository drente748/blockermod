package com.blockermod.platform.vpn

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blockermod.core.BlockingResult
import com.blockermod.core.lockout.NoOpLockoutPolicy
import com.blockermod.core.policy.PolicyEngine
import com.blockermod.core.policy.SafeSearchTable
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Instrumented regression tests for the packed asset loading path (see docs/MANUAL_TESTS.md).
 *
 * On a device the packed lists live inside the installed APK, so an AssetFileDescriptor points at
 * the APK with a nonzero startOffset. The old code mapped the whole channel from offset 0 and
 * parsed the ZIP header, which failed policy-engine construction and stopped the protection
 * before it started. These tests exercise the real asset path on a real Android runtime.
 */
@RunWith(AndroidJUnit4::class)
class AssetRulesInstrumentedTest {

    @Test
    fun packedBlocklistsLoadThroughAssetRulesAndMatchRealDomains() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext

        AssetRules.openBlocklist(context).use { blocklist ->
            assertTrue(blocklist.matcher.matches("www.pornhub.com"), "a known adult domain must match")
            assertFalse(blocklist.matcher.matches("example.com"))
        }

        AssetRules.openMatcher(context, AssetRules.BYPASS_ASSET).use { bypass ->
            assertTrue(bypass.matcher.matches("dns.google"))
        }

        AssetRules.openMatcher(context, AssetRules.UNSUPPORTED_ASSET).use { unsupported ->
            assertTrue(unsupported.matcher.matches("baidu.com"))
        }
    }

    @Test
    fun policyEngineBuildsFromRealAssetsAndBlocks() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext

        AssetRules.openBlocklist(context).use { blocklist ->
            AssetRules.openMatcher(context, AssetRules.BYPASS_ASSET).use { bypass ->
                AssetRules.openMatcher(context, AssetRules.UNSUPPORTED_ASSET).use { unsupported ->
                    val engine = PolicyEngine(
                        allowlist = AssetRules.readAllowlist(context),
                        adultBlocklist = blocklist.matcher,
                        bypassBlocklist = bypass.matcher,
                        unsupportedEngineBlocklist = unsupported.matcher,
                        safeSearchTable = object : SafeSearchTable {
                            override fun lookup(domain: String): String? = null
                        },
                        lockoutPolicy = NoOpLockoutPolicy(),
                    )

                    assertEquals(BlockingResult.Blocked::class, engine.evaluate("www.pornhub.com")::class)
                    assertEquals(BlockingResult.Allowed, engine.evaluate("example.org"))
                }
            }
        }
    }

    @Test
    fun strictResolverListLoadsFromAssets() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val resolvers = AssetRules.readStrictResolvers(context)

        assertTrue(resolvers.size >= KNOWN_RESOLVER_COUNT, "the strict resolver list must be populated")
        assertTrue(resolvers.all { IPV4_REGEX.toRegex().matches(it) }, "every entry must be an IPv4 literal")
    }

    private companion object {
        const val KNOWN_RESOLVER_COUNT: Int = 12
        const val IPV4_REGEX: String =
            "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$"
    }
}
