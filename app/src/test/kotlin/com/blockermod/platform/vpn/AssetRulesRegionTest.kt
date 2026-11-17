package com.blockermod.platform.vpn

import com.blockermod.core.matcher.BinarySearchDomainMatcher
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Regression tests for the packed-asset mapping region.
 *
 * An AssetFileDescriptor wraps the whole APK: the entry lives at [startOffset, declaredLength),
 * not at offset 0. Mapping the entire channel (the old behaviour) parses the APK header as a
 * packed list and fails closed at startup, which prevented the protection from ever starting on
 * a device. These tests simulate a nonzero-offset asset on a plain JVM.
 */
class AssetRulesRegionTest {

    @Test
    fun `the map starts at the asset offset and the matcher reads the packed entries`() {
        val file = File.createTempFile("asset-region", ".bin")
        try {
            val entries = listOf("blocked.example", "deep.other.example")
            val blob = pack(entries)
            // A nonzero offset with garbage in front: the region must start after the prefix.
            val prefix = ByteArray(PREFIX_SIZE) { 0xFF.toByte() }
            FileOutputStream(file).use { it.write(prefix); it.write(blob) }

            val buffer = FileInputStream(file).use { stream ->
                AssetRules.mapAssetRegion(stream.fd, PREFIX_SIZE.toLong(), blob.size.toLong())
            }

            assertEquals(blob.size, buffer.remaining(), "only the asset region must be mapped")
            val matcher = BinarySearchDomainMatcher(buffer)
            assertTrue(matcher.matches("blocked.example"))
            assertTrue(matcher.matches("sub.blocked.example"), "a parent entry must cover its children")
            assertTrue(matcher.matches("deep.other.example"))
            assertFalse(matcher.matches("clean.example"))
        } finally {
            file.delete()
        }
    }

    @Test
    fun `mapping the whole channel from offset zero fails closed like the old bug`() {
        val file = File.createTempFile("asset-region-zero", ".bin")
        try {
            val blob = pack(listOf("blocked.example"))
            val prefix = ByteArray(PREFIX_SIZE) { 0xFF.toByte() }
            FileOutputStream(file).use { it.write(prefix); it.write(blob) }

            FileInputStream(file).use { stream ->
                val whole = stream.channel.map(
                    java.nio.channels.FileChannel.MapMode.READ_ONLY,
                    0L,
                    stream.channel.size(),
                )
                // The old code produced exactly this buffer: the header is not a valid record.
                assertFailsWith<IllegalArgumentException> { BinarySearchDomainMatcher(whole) }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `a region beyond the file end is rejected`() {
        val file = File.createTempFile("asset-region-short", ".bin")
        try {
            FileOutputStream(file).use { it.write(ByteArray(64)) }
            val descriptor = FileInputStream(file).use { it.fd }
            assertFailsWith<IOException> {
                AssetRules.mapAssetRegion(descriptor, 0L, 4096L)
            }
        } finally {
            file.delete()
        }
    }

    /** Packs domains in the format the build script writes and the matcher reads. */
    private fun pack(domains: List<String>): ByteArray {
        val entries = domains
            .map { domain -> domain.split(".").reversed().joinToString("\u0000") }
            .sorted() // ASCII byte order equals the string order for label separators < 0x21
            .map { it.toByteArray(Charsets.US_ASCII) }
        val out = ByteBuffer.allocate(entries.sumOf { it.size + 2 })
        for (entry in entries) {
            out.put((entry.size ushr 8).toByte())
            out.put(entry.size.toByte())
            out.put(entry)
        }
        return out.array()
    }

    private companion object {
        const val PREFIX_SIZE: Int = 512
    }
}
