package com.blockermod.core

/**
 * Contract of the blocking engine.
 *
 * Contracts only: no Android reference and no implementation. The implementation lives in the
 * platform layer (see `core.vpn.BlockerVpnService`).
 */
interface BlockingEngine {

    /** Starts the engine and begins intercepting network traffic. */
    fun start()

    /** Stops the engine and releases the network resources. */
    fun stop()

    /** Current running state. */
    val isRunning: Boolean

    /** Checks a single host and decides whether to allow or block it. */
    fun evaluate(host: String): BlockDecision
}
