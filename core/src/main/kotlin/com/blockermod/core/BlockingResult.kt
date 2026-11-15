package com.blockermod.core

/**
 * Outcome of evaluating a single domain against the policy.
 */
sealed class BlockingResult {

    /** The domain may be resolved normally. */
    object Allowed : BlockingResult()

    /**
     * The domain must not be resolved.
     *
     * @property reason why the domain was blocked.
     */
    data class Blocked(val reason: BlockReason) : BlockingResult()

    /**
     * The domain must be resolved through a different canonical name.
     *
     * The engine only decides; resolving the target and building the DNS answer belongs to the
     * platform layer.
     *
     * @property cnameTarget canonical name the query should be rewritten to.
     * @property original domain that produced the rewrite.
     */
    data class Rewrite(val cnameTarget: String, val original: String) : BlockingResult()

    /**
     * The domain could not be evaluated.
     *
     * @property message description of the failure.
     */
    data class Error(val message: String) : BlockingResult()
}
