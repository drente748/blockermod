package com.blockermod.platform.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Daily blocked-domain counter with a live flow and a rollover check on READ as well as on write.
 * No names are stored, and the counter is intentionally not persisted across process death (C5).
 */
internal class DailyCounter(private val today: () -> Long) {

    private val flow = MutableStateFlow(0L)
    private var currentDay: Long = today()

    val value: StateFlow<Long> = flow.asStateFlow()

    fun record() {
        rolloverIfNeeded()
        flow.value = flow.value + 1
    }

    /** Synchronous read: a new day resets the counter even if nothing was recorded yet. */
    fun read(): Long {
        rolloverIfNeeded()
        return flow.value
    }

    private fun rolloverIfNeeded() {
        val day = today()
        if (day != currentDay) {
            currentDay = day
            flow.value = 0
        }
    }
}
