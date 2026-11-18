package com.blockermod.core.matcher

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The one canonical form used at the resolver boundary (C4; ASCII fast path in C9). */
class DomainNormalizerTest {

    @Test
    fun `unicode and punycode normalize to the same name`() {
        assertEquals(DomainNormalizer.normalize("xn--bcher-kva.example"), DomainNormalizer.normalize("bücher.example"))
    }

    @Test
    fun `case and trailing dots are removed`() {
        assertEquals("example.com", DomainNormalizer.normalize("  ExAmPlE.CoM.  "))
    }

    @Test
    fun `empty names are rejected`() {
        assertNull(DomainNormalizer.normalize(""))
        assertNull(DomainNormalizer.normalize(" ... "))
    }
}
