package com.blockermod.platform.vpn

import com.blockermod.core.BlockingState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Live status of the engine, shared between the service and the user interface.
 *
 * The service publishes the state, the interface only reads it.
 */
object EngineStatus {

    private val stateFlow = MutableStateFlow<BlockingState>(BlockingState.Idle)
    private val counter = DailyCounter { java.time.LocalDate.now().toEpochDay() }

    /** State of the engine, as published by the service. */
    val state: StateFlow<BlockingState> = stateFlow.asStateFlow()

    private val privateDnsFlow = MutableStateFlow(false)

    /** Live warning flag: the UI updates without waiting for a state change (C5). */
    val privateDns: StateFlow<Boolean> = privateDnsFlow.asStateFlow()

    /** Live daily counter; no domain names, no persistence across process restart (C5). */
    val blockedTodayFlow: StateFlow<Long> = counter.value

    /** Publishes whether the device forces private DNS. */
    fun publishPrivateDns(active: Boolean) {
        privateDnsFlow.value = active
    }

    /** True when the device forces private DNS, which bypasses the blocking. */
    fun privateDnsActive(): Boolean = privateDnsFlow.value

    /**
     * Publishes the current state of the engine.
     */
    fun publish(state: BlockingState) {
        stateFlow.value = state
    }

    /** Records one blocked domain and keeps the daily counter. */
    fun recordBlocked() = counter.record()

    /** Number of domains blocked since the beginning of the day (resets on read at midnight). */
    fun blockedToday(): Long = counter.read()
}
