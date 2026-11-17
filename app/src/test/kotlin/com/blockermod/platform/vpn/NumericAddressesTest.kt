package com.blockermod.platform.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** A DNS server string must be a numeric literal, never a hostname resolved by the OS (B9). */
class NumericAddressesTest {

    @Test
    fun `ipv4 and ipv6 literals are accepted`() {
        assertNotNull(NumericAddresses.parse("1.1.1.1"))
        assertNotNull(NumericAddresses.parse("2001:4860:4860::8888"))
    }

    @Test
    fun `a hostname is never passed to the resolver`() {
        assertNull(NumericAddresses.parse("localhost"))
        assertNull(NumericAddresses.parse("dns.google"))
        assertNull(NumericAddresses.parse("999.1.1.1"))
        assertNull(NumericAddresses.parse(""))
    }

    @Test
    fun `parsed literals keep their numeric address`() {
        assertEquals("1.1.1.1", NumericAddresses.parse("1.1.1.1")?.hostAddress)
    }
}
