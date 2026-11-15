package com.blockermod.platform.vpn

import android.content.Context
import com.blockermod.core.DomainMatcher
import com.blockermod.core.matcher.BinarySearchDomainMatcher
import com.blockermod.core.policy.SafeSearchTable
import java.io.IOException
import java.nio.ByteBuffer

/**
 * Loads the rule sets that ship with the application.
 *
 * The packed blocklist is mapped into the memory, so the matcher searches the bytes directly and
 * never parses them at startup.
 */
internal object AssetRules {

    /** Name of the packed blocklist asset. */
    const val BLOCKLIST_ASSET: String = "blocklist.bin"

    /** Name of the safe search table asset. */
    const val SAFESEARCH_ASSET: String = "safesearch.json"

    /**
     * Opens the packed blocklist as a memory map.
     *
     * The caller owns the returned handle and must close it.
     */
    @Throws(IOException::class)
    fun openBlocklist(context: Context): BlocklistHandle {
        val asset = context.assets.openFd(BLOCKLIST_ASSET)
        val descriptor = android.os.ParcelFileDescriptor.dup(asset.fileDescriptor)
        val channel = java.io.FileInputStream(descriptor.fileDescriptor).channel
        val buffer = channel.map(java.nio.channels.FileChannel.MapMode.READ_ONLY, 0L, channel.size())
        return BlocklistHandle(BinarySearchDomainMatcher(buffer), descriptor)
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
     * A mapped blocklist and the descriptor that keeps it alive.
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
