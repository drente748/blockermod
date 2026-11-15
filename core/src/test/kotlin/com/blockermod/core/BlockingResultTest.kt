package com.blockermod.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class BlockingResultTest {

    @Test
    fun `allowed carries no reason`() {
        assertIs<BlockingResult.Allowed>(BlockingResult.Allowed)
    }

    @Test
    fun `blocked carries a reason`() {
        val result = BlockingResult.Blocked(BlockReason.BLOCKLIST)

        assertEquals(BlockReason.BLOCKLIST, result.reason)
    }

    @Test
    fun `blocked keeps the given reason`() {
        assertEquals(BlockReason.USER_PAUSED, BlockingResult.Blocked(BlockReason.USER_PAUSED).reason)
        assertEquals(BlockReason.RECOVERY_MODE, BlockingResult.Blocked(BlockReason.RECOVERY_MODE).reason)
    }

    @Test
    fun `error carries a message`() {
        val result = BlockingResult.Error("resolver unavailable")

        assertEquals("resolver unavailable", result.message)
    }
}
