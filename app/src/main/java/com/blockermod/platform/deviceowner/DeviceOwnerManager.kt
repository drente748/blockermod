package com.blockermod.platform.deviceowner

/**
 * Contract for the device owner mode.
 *
 * Contracts only. Its presence does not mean the app runs in this mode: see docs/ARCHITECTURE.md for
 * why blocking runs in a single mode only.
 */
interface DeviceOwnerManager {

    /** Is the app the current device owner? */
    val isDeviceOwner: Boolean

    /** Packages locked through this mode. */
    fun lockedPackages(): Set<String>

    /** Replaces the list of locked packages. */
    fun setLockedPackages(packages: Set<String>)
}
