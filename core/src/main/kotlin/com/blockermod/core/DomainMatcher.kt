package com.blockermod.core

/**
 * Decides whether a domain matches the block rules.
 *
 * Abstract on purpose: the implementation may be a set, a trie, or a memory-mapped structure,
 * without changing the BlockingEngine contract.
 */
interface DomainMatcher {
    fun matches(domain: String): Boolean
}
