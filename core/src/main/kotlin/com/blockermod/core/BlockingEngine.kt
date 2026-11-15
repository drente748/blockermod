package com.blockermod.core

/**
 * Contract of the blocking engine.
 *
 * Contracts only: no platform reference and no implementation. The implementation lives in the
 * platform layer of the application module.
 */
interface BlockingEngine {

    /** Lifecycle state of the engine. */
    val state: BlockingState

    /** Starts the engine. */
    fun start()

    /** Stops the engine and releases its resources. */
    fun stop()

    /** Evaluates a single domain and returns the decision. */
    fun evaluate(domain: String): BlockingResult
}
