package com.blockermod.platform.vpn

import com.blockermod.core.BlockingState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.LocalDate
import java.util.concurrent.atomic.AtomicLong

/**
 * Live status of the engine, shared between the service and the user interface.
 *
 * The service publishes the state, the interface only reads it.
 */
object EngineStatus {

    private val stateFlow = MutableStateFlow<BlockingState>(BlockingState.Idle)
    private val blockedCount = AtomicLong(0)

    @Volatile
    private var currentDay: Long = today()

    /** State of the engine, as published by the service. */
    val state: StateFlow<BlockingState> = stateFlow.asStateFlow()

    @Volatile
    private var privateDns: Boolean = false

    /**
     * Publishes whether the device forces private DNS.
     */
    fun publishPrivateDns(active: Boolean) {
        privateDns = active
    }

    /**
     * True when the device forces private DNS, which bypasses the blocking.
     */
    fun privateDnsActive(): Boolean = privateDns

    /**
     * Publishes the current state of the engine.
     */
    fun publish(state: BlockingState) {
        stateFlow.value = state
    }

    /**
     * Records one blocked domain and keeps the daily counter.
     */
    fun recordBlocked() {
        val day = today()
        if (day != currentDay) {
            synchronized(this) {
                if (day != currentDay) {
                    currentDay = day
                    blockedCount.set(0)
                }
            }
        }
        blockedCount.incrementAndGet()
    }

    /**
     * Number of domains blocked since the beginning of the day.
     */
    fun blockedToday(): Long = blockedCount.get()

    private fun today(): Long = LocalDate.now().toEpochDay()
}
