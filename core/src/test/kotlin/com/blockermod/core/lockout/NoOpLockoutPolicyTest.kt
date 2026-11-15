package com.blockermod.core.lockout

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class NoOpLockoutPolicyTest {

    @Test
    fun `is never locked`() {
        assertFalse(NoOpLockoutPolicy().isLocked())
    }

    @Test
    fun `has no remaining time`() {
        assertEquals(0L, NoOpLockoutPolicy().remainingMillis())
    }

    @Test
    fun `implements the policy contract`() {
        val policy: LockoutPolicy = NoOpLockoutPolicy()

        assertFalse(policy.isLocked())
        assertEquals(0L, policy.remainingMillis())
    }
}
