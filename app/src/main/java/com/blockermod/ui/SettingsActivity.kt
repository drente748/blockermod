package com.blockermod.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Switch
import com.blockermod.R
import com.blockermod.platform.vpn.AppSettings

/**
 * The settings screen: safe search and strict resolver controls. Both are read when the service
 * starts, so a change takes effect after protection is restarted.
 */
class SettingsActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val safeSearch = findViewById<Switch>(R.id.safeSearchSwitch)
        val strictResolver = findViewById<Switch>(R.id.strictResolverSwitch)

        safeSearch.isChecked = AppSettings.safeSearchEnabled(this)
        safeSearch.setOnCheckedChangeListener { _, checked ->
            AppSettings.setSafeSearchEnabled(this, checked)
        }

        strictResolver.isChecked = AppSettings.strictResolverEnabled(this)
        strictResolver.setOnCheckedChangeListener { _, checked ->
            AppSettings.setStrictResolverEnabled(this, checked)
        }

        val fullTunnel = findViewById<Switch>(R.id.fullTunnelSwitch)
        fullTunnel.isChecked = AppSettings.fullTunnelEnabled(this)
        fullTunnel.setOnCheckedChangeListener { _, checked ->
            AppSettings.setFullTunnelEnabled(this, checked)
        }

        val blockQuic = findViewById<Switch>(R.id.blockQuicSwitch)
        blockQuic.isChecked = AppSettings.blockQuicEnabled(this)
        blockQuic.setOnCheckedChangeListener { _, checked ->
            AppSettings.setBlockQuicEnabled(this, checked)
        }
    }
}
