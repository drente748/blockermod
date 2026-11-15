package com.blockermod.core.policy

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SafeSearchTableTest {

    private val table = InMemorySafeSearchTable(
        mapOf(
            "www.google.com" to "forcesafesearch.google.com",
            "www.bing.com" to "strict.bing.com",
        ),
    )

    @Test
    fun `returns the target of an exact host`() {
        assertEquals("forcesafesearch.google.com", table.lookup("www.google.com"))
    }

    @Test
    fun `returns null for an unknown host`() {
        assertNull(table.lookup("www.example.com"))
    }

    @Test
    fun `does not match a different host of the same service`() {
        assertNull(table.lookup("mail.google.com"))
    }

    @Test
    fun `does not match a subdomain`() {
        assertNull(table.lookup("a.www.google.com"))
    }

    @Test
    fun `does not match an ip address`() {
        assertNull(table.lookup("8.8.8.8"))
    }

    @Test
    fun `does not match a different case`() {
        assertNull(table.lookup("WWW.GOOGLE.COM"))
    }

    @Test
    fun `an empty table never matches`() {
        val empty = InMemorySafeSearchTable(emptyMap())

        assertNull(empty.lookup("www.google.com"))
    }
}
