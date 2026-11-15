package com.blockermod.core

/** Lifecycle state of the blocking engine. */
sealed interface BlockingState {
    data object Idle : BlockingState

    data object Starting : BlockingState

    data object Active : BlockingState

    data class Error(val message: String) : BlockingState
}
