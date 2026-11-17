package com.blockermod.platform.vpn

import android.content.Context
import com.blockermod.core.DomainMatcher
import com.blockermod.core.matcher.BinarySearchDomainMatcher
import com.blockermod.core.policy.SafeSearchTable
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * Loads the rule sets that ship with the application.
 *
 * The packed blocklist is mapped into the memory, so the matcher searches the bytes directly and
 * never parses them at startup.
 */
internal object AssetRules {

    /** Name of the packed blocklist asset. */
    const val BLOCKLIST_ASSET: String = "blocklist.bin"

    /** Name of the packed bypass-attempt list. */
    const val BYPASS_ASSET: String = "bypass.bin"

    /** Name of the packed unsupported-engine list. */
    const val UNSUPPORTED_ASSET: String = "unsupported.bin"

    /** Name of the safe search table asset. */
    const val SAFESEARCH_ASSET: String = "safesearch.json"

    /** Name of the runtime allowlist asset (domains that must never be blocked). */
    const val ALLOWLIST_ASSET: String = "allowlist.txt"

    /** Name of the strict-resolver address asset. */
    const val STRICT_RESOLVERS_ASSET: String = "strict-resolvers.txt"

    /**
     * Reads the encrypted-resolver address list from the assets.
     */
    @Throws(IOException::class)
    fun readStrictResolvers(context: Context): List<String> =
        context.assets.open(STRICT_RESOLVERS_ASSET).bufferedReader().useLines { lines ->
            lines.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .toList()
        }

    /**
     * Opens the packed blocklist as a memory map.
     *
     * The caller owns the returned handle and must close it.
     */
    @Throws(IOException::class)
    fun openBlocklist(context: Context): BlocklistHandle {
        context.assets.openFd(BLOCKLIST_ASSET).use { asset ->
            return openPacked(asset.fileDescriptor, asset.startOffset, asset.declaredLength)
        }
    }

    /**
     * Reads the runtime allowlist shipped with the application.
     */
    @Throws(IOException::class)
    fun readAllowlist(context: Context): DomainMatcher {
        val rules = context.assets.open(ALLOWLIST_ASSET).bufferedReader().useLines { lines ->
            lines.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .toSet()
        }
        return com.blockermod.core.matcher.InMemoryDomainMatcher(rules)
    }

    /**
     * Opens a packed domain list as a matcher, from any of the packed assets.
     *
     * The caller owns the returned handle and must close it: the file descriptor stays open for
     * the lifetime of the matcher so the memory map always has a live backing file.
     */
    @Throws(IOException::class)
    fun openMatcher(context: Context, assetName: String): BlocklistHandle {
        context.assets.openFd(assetName).use { asset ->
            return openPacked(asset.fileDescriptor, asset.startOffset, asset.declaredLength)
        }
    }

    /**
     * Duplicates an asset file descriptor and maps exactly the region the asset descriptor
     * points at.
     *
     * An AssetFileDescriptor wraps the whole APK: its file descriptor is the base APK and the
     * actual entry starts at [startOffset] for [declaredLength] bytes. Mapping from offset 0 with
     * the full channel size would parse the ZIP header as a packed blocklist and fail closed at
     * startup, so the region boundaries must always be used.
     *
     * The duplicated descriptor is kept open for the lifetime of the returned handle; the mapped
     * buffer must never outlive it.
     */
    @Throws(IOException::class)
    fun openPacked(fd: FileDescriptor, startOffset: Long, declaredLength: Long): BlocklistHandle {
        val descriptor = try {
            android.os.ParcelFileDescriptor.dup(fd)
        } catch (exception: IOException) {
            throw IOException("the asset descriptor could not be duplicated", exception)
        }
        val buffer = try {
            mapAssetRegion(descriptor.fileDescriptor, startOffset, declaredLength)
        } catch (exception: IOException) {
            try {
                descriptor.close()
            } catch (ignored: IOException) {
                // the descriptor is already closed
            }
            throw exception
        }
        return BlocklistHandle(BinarySearchDomainMatcher(buffer), descriptor)
    }

    /**
     * Maps exactly [startOffset, startOffset + declaredLength) of the file into memory.
     *
     * Pure JVM helper so tests can verify that the map starts at the asset offset instead of the
     * file start; the Android callers pass the AssetFileDescriptor boundaries.
     */
    @Throws(IOException::class)
    internal fun mapAssetRegion(fd: FileDescriptor, startOffset: Long, declaredLength: Long): ByteBuffer {
        FileInputStream(fd).use { stream ->
            val channel = stream.channel
            if (startOffset < 0L || declaredLength <= 0L || startOffset + declaredLength > channel.size()) {
                throw IOException(
                    "invalid asset region: offset=$startOffset length=$declaredLength size=${channel.size()}",
                )
            }
            return channel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
        }
    }

    /**
     * Reads the safe search table from the assets.
     */
    @Throws(IOException::class)
    fun readSafeSearchTable(context: Context): SafeSearchTable {
        val json = context.assets.open(SAFESEARCH_ASSET).bufferedReader().use { it.readText() }
        return JsonSafeSearchTable(json)
    }

    /**
     * A mapped packed list and the descriptor that keeps it alive.
     */
    class BlocklistHandle(
        val matcher: DomainMatcher,
        private val descriptor: android.os.ParcelFileDescriptor,
    ) : java.io.Closeable {
        override fun close() {
            try {
                descriptor.close()
            } catch (exception: IOException) {
                // the descriptor is already closed
            }
        }
    }
}

/**
 * Safe search table read from the JSON asset.
 *
 * The lookup is an exact host match, as the engine expects.
 */
internal class JsonSafeSearchTable(json: String) : SafeSearchTable {

    private val entries: Map<String, String> = parse(json)

    /**
     * Returns the safe search target of the exact host, or null.
     */
    override fun lookup(domain: String): String? = entries[domain]

    private companion object {
        fun parse(json: String): Map<String, String> {
            val result = HashMap<String, String>()
            val root = org.json.JSONObject(json)
            val entries = root.optJSONObject("entries") ?: return result

            val keys = entries.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val value = entries.optString(key, "")
                if (value.isNotEmpty()) result[key.lowercase()] = value
            }

            return result
        }
    }
}

/**
 * Safe search table that never rewrites anything.
 */
internal object EmptySafeSearchTable : SafeSearchTable {
    override fun lookup(domain: String): String? = null
}
