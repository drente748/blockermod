package com.blockermod.core.matcher

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InMemoryDomainMatcherTest {

    @Test
    fun `matches an exact domain`() {
        val matcher = InMemoryDomainMatcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("ads.example.com"))
    }

    @Test
    fun `matches a subdomain`() {
        val matcher = InMemoryDomainMatcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("tracker.ads.example.com"))
    }

    @Test
    fun `does not match a partial label`() {
        val matcher = InMemoryDomainMatcher(listOf("ads.example.com"))

        assertFalse(matcher.matches("notads.example.com"))
    }

    @Test
    fun `does not match an unrelated domain`() {
        val matcher = InMemoryDomainMatcher(listOf("ads.example.com"))

        assertFalse(matcher.matches("example.com"))
    }

    @Test
    fun `matches regardless of the case and the trailing dot`() {
        val matcher = InMemoryDomainMatcher(listOf("ads.example.com"))

        assertTrue(matcher.matches("ADS.Example.COM."))
    }

    @Test
    fun `matches an internationalized domain`() {
        val matcher = InMemoryDomainMatcher(listOf("xn--bcher-kva.example"))

        assertTrue(matcher.matches("bücher.example"))
    }

    @Test
    fun `returns false for an empty rule set`() {
        val matcher = InMemoryDomainMatcher(emptyList())

        assertFalse(matcher.matches("ads.example.com"))
    }
}
