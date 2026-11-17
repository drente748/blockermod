package com.blockermod.core.policy

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class NetworkSelectorTest {

    private val selector = NetworkSelector()

    @Test
    fun `ignores vpn, non internet and losing networks`() {
        val candidates = listOf(
            candidate("vpn", isVpn = true, isValidated = true),
            candidate("nointernet", hasInternet = false, isValidated = true),
            candidate("losing", isLosing = true, isValidated = true),
        )

        assertNull(selector.select(candidates))
    }

    @Test
    fun `prefers validated network regardless of insertion order`() {
        val candidates = listOf(
            candidate("wifi", isValidated = false),
            candidate("mobile", isValidated = true),
        )

        assertEquals("mobile", selector.select(candidates)?.id)
    }

    @Test
    fun `keeps current network when still eligible to avoid flapping`() {
        val candidates = listOf(
            candidate("wifi", isValidated = true),
            candidate("mobile", isValidated = true),
        )

        assertEquals("mobile", selector.select(candidates, currentId = "mobile")?.id)
    }

    @Test
    fun `empty dns list does not disqualify a network`() {
        val candidates = listOf(candidate("wifi", dns = emptyList()))

        assertEquals("wifi", selector.select(candidates)?.id)
    }

    @Test
    fun `deterministic tie break by id`() {
        val candidates = listOf(candidate("z"), candidate("a"))

        assertEquals("a", selector.select(candidates)?.id)
    }

    private fun candidate(
        id: String,
        hasInternet: Boolean = true,
        isVpn: Boolean = false,
        isValidated: Boolean = true,
        isLosing: Boolean = false,
        dns: List<String> = listOf("1.1.1.1"),
    ) = NetworkCandidate(id, hasInternet, isVpn, isValidated, isLosing, dns)
}
