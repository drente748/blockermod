package com.blockermod.ui

/**
 * Pure "dirty" detection for the settings screen: the restart button appears only when a control
 * changed AND protection is active (C6). No Android types, so the rule has a JVM test.
 */
internal object SettingsChanges {

    data class Snapshot(
        val safeSearch: Boolean,
        val strictResolver: Boolean,
        val fullTunnel: Boolean,
        val blockQuic: Boolean,
    )

    fun needsRestart(current: Snapshot, original: Snapshot, protectionActive: Boolean): Boolean =
        protectionActive && current != original
}
