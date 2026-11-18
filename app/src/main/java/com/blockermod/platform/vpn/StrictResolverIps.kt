package com.blockermod.platform.vpn

import android.content.Context
import android.os.Build

/**
 * Encrypted-resolver addresses routed into the tunnel so their DoT/DoH cannot bypass the filter.
 *
 * The addresses are loaded from the `strict-resolvers.txt` asset once at startup; no IP is hardcoded
 * in source and no hostname is resolved. Routing them costs battery (the tunnel reads and drops
 * more packets than it answers), but it is the only way for an ordinary installed app to stop
 * encrypted DNS to resolvers the user did not choose. System Private DNS pointed at a custom host
 * still needs the user to turn it off; the interface warns when that is detected.
 */
internal object StrictResolverIps {

    /** Master switch of the feature; kept for callers that do not have a Context. */
    const val STRICT_RESOLVER_IPS_ENABLED: Boolean = true

    @Volatile
    private var enabled: Boolean = true

    /** Applies the user preference. Disabled means no routes are added. */
    fun setEnabled(value: Boolean) {
        enabled = STRICT_RESOLVER_IPS_ENABLED && value
    }

    /** Ports dropped for those addresses: DNS over TLS and DNS over HTTPS. */
    val DROPPED_PORTS: Set<Int> = setOf(853, 443)

    @Volatile
    private var routesList: List<String> = emptyList()

    @Volatile
    private var resolverSet: StrictResolverSet = StrictResolverSet(emptyList(), ::parseLiteral)

    /** Loads the address list from the asset. Must be called before the tunnel starts. */
    fun initialize(context: Context) {
        if (!STRICT_RESOLVER_IPS_ENABLED || routesList.isNotEmpty()) return
        val loaded = AssetRules.readStrictResolvers(context)
        routesList = loaded
        resolverSet = StrictResolverSet(loaded, ::parseLiteral)
    }

    /** Routes to add to the tunnel interface. */
    fun routes(): List<String> = if (enabled) routesList else emptyList()

    /** True when the destination is a strict resolver and the feature is on. */
    fun isStrictResolver(destinationAddress: Int): Boolean =
        enabled && resolverSet.values.contains(destinationAddress)

    /** True when the port must be dropped for strict resolvers. */
    fun isDroppedPort(port: Int): Boolean = DROPPED_PORTS.contains(port)

    /** O(1) after one parse of the incoming literal (C3). */
    fun containsAddress(address: String): Boolean = resolverSet.contains(address)

    /** Numeric literal only: Android's parseNumericAddress on 33+, the pure-JVM helper before. */
    private fun parseLiteral(value: String): Int? {
        val parsed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            android.net.InetAddresses.parseNumericAddress(value)
        } else {
            NumericAddresses.parse(value)
        } ?: return null
        val bytes = parsed.address
        if (bytes.size != 4) return null // strict-resolver routes are IPv4 /32
        return bytes.fold(0) { accumulator, byte -> (accumulator shl 8) or (byte.toInt() and 0xFF) }
    }
}
