package com.blockermod.core

/** Outcome of evaluating a single domain. */
sealed interface BlockingResult {
    data object Allowed : BlockingResult

    data class Blocked(val reason: BlockReason) : BlockingResult

    data class Error(val message: String) : BlockingResult
}
