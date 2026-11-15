package com.blockermod.core

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DomainMatcherTest {

    private val matcher = object : DomainMatcher {
        override fun matches(domain: String): Boolean =
            domain == "ads.example.com" || domain.endsWith(".ads.example.com")
    }

    @Test
    fun `matches exact domain`() {
        assertTrue(matcher.matches("ads.example.com"))
    }

    @Test
    fun `matches subdomain`() {
        assertTrue(matcher.matches("tracker.ads.example.com"))
    }

    @Test
    fun `does not match unrelated domain`() {
        assertFalse(matcher.matches("example.com"))
    }
}
