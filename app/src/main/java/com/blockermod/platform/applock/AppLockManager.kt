package com.blockermod.platform.applock

/**
 * Contract for application locking: preventing an app from being used until the user passes a
 * verification step.
 *
 * Contracts only. The implementation depends on system capabilities and user-granted permission,
 * and is not part of the current phase.
 */
interface AppLockManager {

    /** Is the given app currently locked? */
    fun isLocked(packageName: String): Boolean

    /** Locks an app. */
    fun lock(packageName: String)

    /** Unlocks an app. */
    fun unlock(packageName: String)
}
