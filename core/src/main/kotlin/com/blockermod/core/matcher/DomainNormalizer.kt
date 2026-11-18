package com.blockermod.core.matcher

import java.net.IDN
import java.util.Locale

/**
 * Normalization shared by every matcher implementation.
 */
object DomainNormalizer {

    /**
     * Normalizes a domain: trimmed, lower cased, without the trailing dot, and converted to
     * punycode when it carries non ASCII characters.
     *
     * Returns null when the domain cannot be normalized, for example when it is empty or when it
     * breaks the label rules.
     */
    fun normalize(domain: String): String? {
        var value = domain.trim().trimEnd('.')
        if (value.isEmpty()) return null

        value = value.lowercase(Locale.ROOT)

        return try {
            IDN.toASCII(value).trimEnd('.').lowercase(Locale.ROOT)
        } catch (exception: IllegalArgumentException) {
            null
        }
    }
}
