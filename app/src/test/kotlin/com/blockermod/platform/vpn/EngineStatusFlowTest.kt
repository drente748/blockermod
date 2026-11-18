package com.blockermod.platform.vpn

import kotlin.test.Test
import kotlin.test.assertEquals

/** Live flows and midnight reset on read (C5). */
class EngineStatusFlowTest {

    @Test
    fun `the day resets on read even without a new block`() {
        var day = 100L
        val counter = DailyCounter { day }

        counter.record()
        counter.record()
        assertEquals(2L, counter.read())

        day = 101L
        assertEquals(0L, counter.read(), "midnight must reset even when nobody records a block")
        assertEquals(0L, counter.value.value)
    }

    @Test
    fun `the private dns flow publishes immediately`() {
        EngineStatus.publishPrivateDns(true)
        assertEquals(true, EngineStatus.privateDns.value)
        assertEquals(true, EngineStatus.privateDnsActive())
        EngineStatus.publishPrivateDns(false)
        assertEquals(false, EngineStatus.privateDns.value)
    }
}
