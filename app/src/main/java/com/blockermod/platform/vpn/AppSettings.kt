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
     * True when the strict resolver mode is enabled; it is disabled by default.
     */
    fun strictResolverEnabled(context: Context): Boolean =
        preferences(context).getBoolean(KEY_STRICT_RESOLVER, false)

    /**
     * Stores the strict resolver preference.
     */
    fun setStrictResolverEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit { putBoolean(KEY_STRICT_RESOLVER, enabled) }
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
}
