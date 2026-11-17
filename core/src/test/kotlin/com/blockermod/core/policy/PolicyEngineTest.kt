package com.blockermod.core.policy

import com.blockermod.core.BlockReason
import com.blockermod.core.BlockingResult
import com.blockermod.core.DomainMatcher
import com.blockermod.core.lockout.LockoutPolicy
import com.blockermod.core.matcher.InMemoryDomainMatcher
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PolicyEngineTest {

    @Test
    fun `lockout blocks every domain`() {
        val engine = engine(lockoutPolicy = LockedOutPolicy)

        val result = engine.evaluate("example.com")

        assertEquals(BlockingResult.Blocked(BlockReason.USER_PAUSED), result)
    }

    @Test
    fun `lockout wins over the allowlist`() {
        val engine = engine(allowlist = setOf("example.com"), lockoutPolicy = LockedOutPolicy)

        val result = engine.evaluate("example.com")

        assertEquals(BlockingResult.Blocked(BlockReason.USER_PAUSED), result)
    }

    @Test
    fun `canary domain is blocked`() {
        val engine = engine()

        val result = engine.evaluate("use-application-dns.net")

        assertEquals(BlockingResult.Blocked(BlockReason.CANARY), result)
    }

    @Test
    fun `canary domain is blocked even when it is allowlisted`() {
        val engine = engine(allowlist = setOf("use-application-dns.net"))

        val result = engine.evaluate("use-application-dns.net")

        assertEquals(BlockingResult.Blocked(BlockReason.CANARY), result)
    }

    @Test
    fun `safe search host is rewritten`() {
        val engine = engine()

        val result = engine.evaluate("www.google.com")

        assertEquals(BlockingResult.Rewrite("forcesafesearch.google.com", "www.google.com"), result)
    }

    @Test
    fun `rewrite carries the queried domain`() {
        val engine = engine()

        val result = engine.evaluate("WWW.Google.COM.")

        assertIs<BlockingResult.Rewrite>(result)
        assertEquals("forcesafesearch.google.com", result.cnameTarget)
        assertEquals("www.google.com", result.original)
    }

    @Test
    fun `safe search rewrite wins over the allowlist`() {
        val engine = engine(allowlist = setOf("www.google.com"))

        val result = engine.evaluate("www.google.com")

        assertIs<BlockingResult.Rewrite>(result)
    }

    @Test
    fun `rewrite is returned for every query type`() {
        // The engine does not know the query type: an HTTPS or SVCB query cannot carry a CNAME, and
        // the platform layer turns the rewrite into a no data answer. The decision stays a rewrite.
        val engine = engine()

        val result = engine.evaluate("www.google.com")

        assertIs<BlockingResult.Rewrite>(result)
    }

    @Test
    fun `allowlisted domain is allowed`() {
        val engine = engine(allowlist = setOf("example.com"))

        val result = engine.evaluate("example.com")

        assertEquals(BlockingResult.Allowed, result)
    }

    @Test
    fun `allowlist covers subdomains`() {
        val engine = engine(allowlist = setOf("example.com"))

        val result = engine.evaluate("app.example.com")

        assertEquals(BlockingResult.Allowed, result)
    }

    @Test
    fun `allowlist overrides the adult blocklist`() {
        val engine = engine(
            allowlist = setOf("example.com"),
            adultBlocklist = setOf("example.com"),
        )

        val result = engine.evaluate("example.com")

        assertEquals(BlockingResult.Allowed, result)
    }

    @Test
    fun `adult domain is blocked`() {
        val engine = engine(adultBlocklist = setOf("adult.example"))

        val result = engine.evaluate("adult.example")

        assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_ADULT), result)
    }

    @Test
    fun `adult blocklist covers subdomains`() {
        val engine = engine(adultBlocklist = setOf("adult.example"))

        val result = engine.evaluate("video.adult.example")

        assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_ADULT), result)
    }

    @Test
    fun `bypass domain is blocked`() {
        val engine = engine(bypassBlocklist = setOf("bypass.example"))

        val result = engine.evaluate("bypass.example")

        assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_BYPASS), result)
    }

    @Test
    fun `unsupported engine domain is blocked`() {
        val engine = engine(unsupportedEngineBlocklist = setOf("unsupported.example"))

        val result = engine.evaluate("unsupported.example")

        assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_UNSUPPORTED_ENGINE), result)
    }

    @Test
    fun `adult blocklist is evaluated before the bypass blocklist`() {
        val engine = engine(
            adultBlocklist = setOf("both.example"),
            bypassBlocklist = setOf("both.example"),
        )

        val result = engine.evaluate("both.example")

        assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_ADULT), result)
    }

    @Test
    fun `unknown domain is allowed`() {
        val engine = engine()

        val result = engine.evaluate("unknown.example")

        assertEquals(BlockingResult.Allowed, result)
    }

    @Test
    fun `local use names are allowed even when a list carries them`() {
        // Hosts sources historically contain "127.0.0.1 localhost" (B1); blocking it would break
        // every application that resolves localhost.
        val engine = engine(adultBlocklist = setOf("localhost", "sub.localhost"))

        assertEquals(BlockingResult.Allowed, engine.evaluate("localhost"))
        assertEquals(BlockingResult.Allowed, engine.evaluate("foo.localhost"))
        assertEquals(BlockingResult.Allowed, engine.evaluate("localhost.localdomain"))
        assertEquals(BlockingResult.Allowed, engine.evaluate("router.lan"))
        assertEquals(BlockingResult.Allowed, engine.evaluate("printer"))
    }

    @Test
    fun `a normal domain sharing a local word is still blocked`() {
        val engine = engine(adultBlocklist = setOf("evil-localhost-keeper.com"))

        assertEquals(BlockingResult.Blocked(BlockReason.BLOCKLIST_ADULT), engine.evaluate("evil-localhost-keeper.com"))
    }

    @Test
    fun `default lockout policy does not change the result`() {
        val withDefault = engine()
        val withNoOp = engine(lockoutPolicy = NoOpLockout)

        assertEquals(withNoOp.evaluate("adult.example"), withDefault.evaluate("adult.example"))
        assertEquals(BlockingResult.Allowed, withDefault.evaluate("unknown.example"))
    }

    @Test
    fun `constructor fails when a rule source cannot answer`() {
        assertFailsWith<IllegalStateException> {
            engineWithBrokenRuleSource()
        }
    }

    @Test
    fun `constructor fails when the safe search table cannot answer`() {
        assertFailsWith<IllegalStateException> {
            engine(safeSearchTable = BrokenTable)
        }
    }

    @Test
    fun `evaluate never throws on odd inputs`() {
        val engine = engine(
            allowlist = setOf("example.com"),
            adultBlocklist = setOf("adult.example"),
        )

        val inputs = listOf(
            "",
            " ",
            ".",
            "..",
            "example.com.",
            "EXAMPLE.COM",
            "a".repeat(300),
            "مثال.eg",
            "a b.example",
            "..example.com",
            "\u0000",
        )

        for (input in inputs) {
            val result = engine.evaluate(input)
            assertTrue(
                result is BlockingResult.Allowed ||
                    result is BlockingResult.Blocked ||
                    result is BlockingResult.Rewrite ||
                    result is BlockingResult.Error,
            )
        }
    }

    private fun engine(
        allowlist: Set<String> = emptySet(),
        adultBlocklist: Set<String> = emptySet(),
        bypassBlocklist: Set<String> = emptySet(),
        unsupportedEngineBlocklist: Set<String> = emptySet(),
        safeSearchTable: SafeSearchTable = DefaultSafeSearchTable,
        lockoutPolicy: LockoutPolicy = NoOpLockout,
    ): PolicyEngine = PolicyEngine(
        allowlist = InMemoryDomainMatcher(allowlist),
        adultBlocklist = InMemoryDomainMatcher(adultBlocklist),
        bypassBlocklist = InMemoryDomainMatcher(bypassBlocklist),
        unsupportedEngineBlocklist = InMemoryDomainMatcher(unsupportedEngineBlocklist),
        safeSearchTable = safeSearchTable,
        lockoutPolicy = lockoutPolicy,
    )

    private fun engineWithBrokenRuleSource(): PolicyEngine = PolicyEngine(
        allowlist = InMemoryDomainMatcher(emptySet()),
        adultBlocklist = BrokenMatcher,
        bypassBlocklist = InMemoryDomainMatcher(emptySet()),
        unsupportedEngineBlocklist = InMemoryDomainMatcher(emptySet()),
        safeSearchTable = DefaultSafeSearchTable,
        lockoutPolicy = NoOpLockout,
    )

    private object NoOpLockout : LockoutPolicy {
        override fun isLocked(): Boolean = false
        override fun remainingMillis(): Long = 0L
    }

    private object LockedOutPolicy : LockoutPolicy {
        override fun isLocked(): Boolean = true
        override fun remainingMillis(): Long = 60_000L
    }

    private object BrokenMatcher : DomainMatcher {
        override fun matches(domain: String): Boolean = error("rule source is not loaded")
    }

    private object BrokenTable : SafeSearchTable {
        override fun lookup(domain: String): String? = error("table is not loaded")
    }

    private object DefaultSafeSearchTable : SafeSearchTable {
        private val entries = mapOf("www.google.com" to "forcesafesearch.google.com")

        override fun lookup(domain: String): String? = entries[domain]
    }
}
