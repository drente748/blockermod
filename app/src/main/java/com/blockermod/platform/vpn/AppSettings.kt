package com.blockermod.platform.vpn

import android.content.Context
import androidx.core.content.edit

/**
 * User settings, kept in the shared preferences.
 *
 * The settings are read by the service when it builds the engine, and written by the settings
 * screen.
 */
internal object AppSettings {

    /** Name of the preferences file. */
    private const val PREFERENCES = "blockermod_settings"

    /** Key of the safe search switch. */
    private const val KEY_SAFE_SEARCH = "safe_search_enabled"

    /** Key of the strict resolver switch. */
    private const val KEY_STRICT_RESOLVER = "strict_resolver_ips_enabled"

    /** Key of the experimental full-tunnel switch. */
    private const val KEY_FULL_TUNNEL = "full_tunnel_enabled"

    /** Key of the optional, off-by-default QUIC/HTTP3 block. */
    private const val KEY_BLOCK_QUIC = "block_quic_enabled"

    /**
     * True when the safe search rewrite is enabled; it is enabled by default.
     */
    fun safeSearchEnabled(context: Context): Boolean =
        preferences(context).getBoolean(KEY_SAFE_SEARCH, true)

    /**
     * Stores the safe search preference.
     */
    fun setSafeSearchEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit { putBoolean(KEY_SAFE_SEARCH, enabled) }
    }

    /**
     * True when the strict resolver mode is enabled; it is enabled by default.
     */
    fun strictResolverEnabled(context: Context): Boolean =
        preferences(context).getBoolean(KEY_STRICT_RESOLVER, true)

    /**
     * Stores the strict resolver preference.
     */
    fun setStrictResolverEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit { putBoolean(KEY_STRICT_RESOLVER, enabled) }
    }

    /**
     * True when the experimental full-tunnel engine is enabled. Off by default: the DNS-only tunnel
     * is the stable mode, the full tunnel relays all TCP/UDP and costs more battery.
     */
    fun fullTunnelEnabled(context: Context): Boolean =
        preferences(context).getBoolean(KEY_FULL_TUNNEL, false)

    fun setFullTunnelEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit { putBoolean(KEY_FULL_TUNNEL, enabled) }
    }

    /**
     * Blocks UDP/443 globally. Off by default: QUIC carries HTTP/3 for the whole web, so blocking it
     * breaks normal sites and forces fallback to TCP. Only enable with a deliberate decision.
     */
    fun blockQuicEnabled(context: Context): Boolean =
        preferences(context).getBoolean(KEY_BLOCK_QUIC, false)

    fun setBlockQuicEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit { putBoolean(KEY_BLOCK_QUIC, enabled) }
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
}
