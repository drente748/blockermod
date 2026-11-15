package com.blockermod.platform.vpn

import com.blockermod.core.BlockingResult
import java.util.ArrayDeque

/**
 * Bounded trail of the decisions taken while the debug mode is on.
 *
 * The trail only stores references: no formatting happens in the packet path, the service drains
 * the trail and formats it away from the hot path.
 */
internal class DecisionTrail(private val capacity: Int = DEFAULT_CAPACITY) {

    private val entries = ArrayDeque<BlockingResult>(capacity)

    /**
     * Appends a decision, dropping the oldest one when the trail is full.
     */
    @Synchronized
    fun record(decision: BlockingResult) {
        if (entries.size >= capacity) entries.removeFirst()
        entries.addLast(decision)
    }

    /**
     * Returns the recorded decisions and empties the trail.
     */
    @Synchronized
    fun drain(): List<BlockingResult> {
        val drained = entries.toList()
        entries.clear()
        return drained
    }

    /**
     * Number of decisions currently held.
     */
    @Synchronized
    fun size(): Int = entries.size

    companion object {
        /** Maximum number of decisions kept in the trail. */
        const val DEFAULT_CAPACITY: Int = 128
    }
}
