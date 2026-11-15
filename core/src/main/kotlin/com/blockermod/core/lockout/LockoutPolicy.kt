package com.blockermod.core.lockout

/**
 * Contract of the lockout policy.
 *
 * The policy decides whether the user is currently locked out and for how long. Implementations
 * that persist state, react to device boot, or offer a recovery code belong to a later wave; this
 * contract only describes what the engine may ask.
 */
interface LockoutPolicy {

    /** True while the lockout is active. */
    fun isLocked(): Boolean

    /** Remaining lockout time in milliseconds; zero when the user is not locked out. */
    fun remainingMillis(): Long
}

/**
 * Lockout policy that never locks anything.
 *
 * Used as the default implementation while the real policy is not built yet.
 */
class NoOpLockoutPolicy : LockoutPolicy {

    /** Always false: this policy never locks the user out. */
    override fun isLocked(): Boolean = false

    /** Always zero: this policy never keeps the user locked out. */
    override fun remainingMillis(): Long = 0L
}
