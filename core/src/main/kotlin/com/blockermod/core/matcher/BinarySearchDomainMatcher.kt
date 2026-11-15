package com.blockermod.core.matcher

import com.blockermod.core.DomainMatcher
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Domain matcher backed by a packed blocklist stored in a [ByteBuffer] and searched with a binary
 * search over byte comparisons.
 *
 * ### Packed format
 *
 * The buffer is a sequence of records, each one made of a two byte big endian length followed by
 * the entry bytes:
 *
 * ```
 * [length:2][entry bytes][length:2][entry bytes]...
 * ```
 *
 * An entry holds the reversed labels of a domain joined by a zero byte, for example the domain
 * `ads.example.com` is stored as `com\0example\0ads`. Zero is safe as a separator because it never
 * appears inside a wire label.
 *
 * Records must be sorted in ascending byte order and must not repeat; the constructor rejects any
 * buffer that breaks that rule.
 *
 * ### Matching semantics
 *
 * A stored domain blocks itself and every subdomain of it. The match happens on label boundaries
 * only, so `notads.example.com` is not covered by the entry `ads.example.com`.
 *
 * Domains are normalized before matching: lower cased, stripped of the trailing dot, and converted
 * to punycode with [IDN] when they contain non ASCII characters.
 */
class BinarySearchDomainMatcher(buffer: ByteBuffer) : DomainMatcher {

    private val data: ByteBuffer = buffer.duplicate().order(ByteOrder.BIG_ENDIAN)

    private val offsets: IntArray = readOffsets(data)

    init {
        validateSorted(data, offsets)
    }

    /**
     * Returns true when the domain, or any of its parent domains, is present in the packed list.
     *
     * @param domain domain to check; normalized before matching.
     */
    override fun matches(domain: String): Boolean {
        val normalized = normalize(domain) ?: return false
        val labels = normalized.split('.').filter { it.isNotEmpty() }
        if (labels.isEmpty()) return false

        val reversed = labels.reversed()
        val ends = IntArray(reversed.size)
        val packed = ByteArray(reversed.sumOf { it.length + 1 } - 1)
        var position = 0

        for (index in reversed.indices) {
            if (index > 0) packed[position++] = LABEL_SEPARATOR
            val bytes = reversed[index].toByteArray(Charsets.US_ASCII)
            bytes.copyInto(packed, position)
            position += bytes.size
            ends[index] = position
        }

        for (index in reversed.indices.reversed()) {
            if (contains(packed, ends[index])) return true
        }

        return false
    }

    private fun contains(target: ByteArray, targetLength: Int): Boolean {
        var low = 0
        var high = offsets.size - 1

        while (low <= high) {
            val middle = (low + high) ushr 1
            val start = offsets[middle]
            val length =
                ((data.get(start).toInt() and 0xFF) shl 8) or (data.get(start + 1).toInt() and 0xFF)

            val comparison = compare(target, targetLength, start + 2, length)
            if (comparison == 0) return true
            if (comparison < 0) high = middle - 1 else low = middle + 1
        }

        return false
    }

    private fun compare(target: ByteArray, targetLength: Int, offset: Int, length: Int): Int {
        val shared = minOf(targetLength, length)
        for (index in 0 until shared) {
            val left = target[index].toInt() and 0xFF
            val right = data.get(offset + index).toInt() and 0xFF
            if (left != right) return if (left < right) -1 else 1
        }
        return targetLength.compareTo(length)
    }

    private fun normalize(domain: String): String? = DomainNormalizer.normalize(domain)

    private companion object {
        /** Separator byte between the reversed labels of an entry. */
        private const val LABEL_SEPARATOR: Byte = 0

        private fun readOffsets(data: ByteBuffer): IntArray {
            val found = ArrayList<Int>()
            var position = 0

            while (position < data.limit()) {
                if (position + 2 > data.limit()) {
                    throw IllegalArgumentException("truncated record header at offset $position")
                }
                val length =
                    ((data.get(position).toInt() and 0xFF) shl 8) or
                        (data.get(position + 1).toInt() and 0xFF)
                if (position + 2 + length > data.limit()) {
                    throw IllegalArgumentException("truncated record body at offset $position")
                }
                found.add(position)
                position += 2 + length
            }

            return found.toIntArray()
        }

        private fun validateSorted(data: ByteBuffer, offsets: IntArray) {
            for (index in 1 until offsets.size) {
                val previous = offsets[index - 1]
                val current = offsets[index]
                val previousLength =
                    ((data.get(previous).toInt() and 0xFF) shl 8) or
                        (data.get(previous + 1).toInt() and 0xFF)
                val currentLength =
                    ((data.get(current).toInt() and 0xFF) shl 8) or
                        (data.get(current + 1).toInt() and 0xFF)

                val comparison = compareEntries(data, previous + 2, previousLength, current + 2, currentLength)
                if (comparison >= 0) {
                    throw IllegalArgumentException("blocklist entries must be sorted and unique")
                }
            }
        }

        private fun compareEntries(
            data: ByteBuffer,
            leftOffset: Int,
            leftLength: Int,
            rightOffset: Int,
            rightLength: Int,
        ): Int {
            val shared = minOf(leftLength, rightLength)
            for (index in 0 until shared) {
                val left = data.get(leftOffset + index).toInt() and 0xFF
                val right = data.get(rightOffset + index).toInt() and 0xFF
                if (left != right) return if (left < right) -1 else 1
            }
            return leftLength.compareTo(rightLength)
        }
    }
}
