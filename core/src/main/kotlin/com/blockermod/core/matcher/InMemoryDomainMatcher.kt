package com.blockermod.core.matcher

import com.blockermod.core.DomainMatcher

/**
 * Matcher over a set of rules kept in memory.
 *
 * The matching semantics are the same as [BinarySearchDomainMatcher]: a rule matches the domain
 * itself and every subdomain of it, on label boundaries only, so `notads.example.com` is not
 * covered by the rule `ads.example.com`.
 *
 * The lookup is linear over the rule set, which suits small lists; large lists belong in the
 * packed matcher.
 */
class InMemoryDomainMatcher(rules: Collection<String>) : DomainMatcher {

    private val normalizedRules: Set<String> =
        rules.mapNotNull { DomainNormalizer.normalize(it) }.toSet()

    /**
     * Returns true when the domain, or one of its parent domains, is part of the rule set.
     */
    override fun matches(domain: String): Boolean {
        val normalized = DomainNormalizer.normalize(domain) ?: return false

        for (rule in normalizedRules) {
            if (normalized == rule || normalized.endsWith(".$rule")) return true
        }

        return false
    }
}
