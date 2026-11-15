package com.blockermod.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Switch
import com.blockermod.R
import com.blockermod.platform.vpn.AppSettings

/**
 * The settings screen: the safe search switch and the reserved strict resolver switch.
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
    }
}
