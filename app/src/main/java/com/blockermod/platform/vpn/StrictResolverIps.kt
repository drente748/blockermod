package com.blockermod.platform.vpn

import java.net.InetAddress

/**
 * Addresses of the strict resolvers that may be routed through the tunnel.
 *
 * The feature is **disabled by default**: it routes a second set of addresses into the tunnel and
 * drops every port but 53 for them, which keeps the encrypted resolvers from bypassing the
 * blocking. Routing more addresses into the tunnel costs battery, because the tunnel has to read
 * and answer more packets; the cost is only worth it when the strict resolvers are actually used.
 *
 * The address list stays empty until the license of the sources is cleared, see
 * `docs/LICENSE_DECISIONS.md`. While the list is empty the feature has no effect whatever the
 * switch says.
 */
internal object StrictResolverIps {

    /** Master switch of the feature; disabled by default. */
    const val STRICT_RESOLVER_IPS_ENABLED: Boolean = false

    /**
     * Addresses routed through the tunnel when the feature is on.
     *
     * Empty until the license decision is taken.
     */
    val STRICT_RESOLVER_IPS: List<String> = emptyList()

    /**
     * Ports dropped for those addresses: encrypted DNS over TLS and DNS over HTTPS.
     *
     * Only the plain DNS port stays allowed.
     */
    val DROPPED_PORTS: Set<Int> = setOf(853, 443)

    private val addresses: Set<Int> by lazy {
        STRICT_RESOLVER_IPS.mapNotNull { literal(it) }.toSet()
    }

    /**
     * Routes to add to the tunnel interface; empty while the feature is off.
     */
    fun routes(): List<String> =
        if (STRICT_RESOLVER_IPS_ENABLED) STRICT_RESOLVER_IPS else emptyList()

    /**
     * True when the destination address is one of the strict resolvers and the feature is on.
     */
    fun isStrictResolver(destinationAddress: Int): Boolean =
        STRICT_RESOLVER_IPS_ENABLED && addresses.contains(destinationAddress)

    /**
     * True when the port must be dropped for the strict resolvers.
     */
    fun isDroppedPort(port: Int): Boolean = DROPPED_PORTS.contains(port)

    private fun literal(value: String): Int? = try {
        InetAddress.getByName(value).address.fold(0) { accumulator, byte -> (accumulator shl 8) or (byte.toInt() and 0xFF) }
    } catch (exception: java.net.UnknownHostException) {
        null
    }
}
