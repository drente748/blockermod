package com.blockermod.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.Switch
import com.blockermod.R
import com.blockermod.platform.vpn.AppSettings
import com.blockermod.platform.vpn.BlockerVpnService
import com.blockermod.platform.vpn.EngineStatus
import com.blockermod.core.BlockingState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * The settings screen. Changes are written immediately but only take effect when the user taps
 * "Apply & restart protection": no silent restart, no ambiguous "restart manually" instruction.
 */
class SettingsActivity : Activity() {

    private var scope: CoroutineScope? = null
    private var original = snapshot()
    private var current = original

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val safeSearch = findViewById<Switch>(R.id.safeSearchSwitch)
        val strictResolver = findViewById<Switch>(R.id.strictResolverSwitch)
        strictResolver.isChecked = original.strictResolver
        safeSearch.isChecked = original.safeSearch
        val fullTunnel = findViewById<Switch>(R.id.fullTunnelSwitch)
        fullTunnel.isChecked = original.fullTunnel
        val blockQuic = findViewById<Switch>(R.id.blockQuicSwitch)
        blockQuic.isChecked = original.blockQuic

        val apply = findViewById<Button>(R.id.applyRestartButton)
        fun changed() {
            current = SettingsChanges.Snapshot(
                safeSearch.isChecked, strictResolver.isChecked, fullTunnel.isChecked, blockQuic.isChecked,
            )
            refreshApply(apply)
        }
        safeSearch.setOnCheckedChangeListener { _, checked -> AppSettings.setSafeSearchEnabled(this, checked); changed() }
        strictResolver.setOnCheckedChangeListener { _, checked -> AppSettings.setStrictResolverEnabled(this, checked); changed() }
        fullTunnel.setOnCheckedChangeListener { _, checked -> AppSettings.setFullTunnelEnabled(this, checked); changed() }
        blockQuic.setOnCheckedChangeListener { _, checked -> AppSettings.setBlockQuicEnabled(this, checked); changed() }

        apply.setOnClickListener { applyAndRestart(apply) }
    }

    override fun onStart() {
        super.onStart()
        scope = CoroutineScope(Dispatchers.Main + SupervisorJob()).also { active ->
            active.launch {
                EngineStatus.state.collect { refreshApply(findViewById<Button>(R.id.applyRestartButton)) }
            }
        }
    }

    override fun onStop() {
        scope?.cancel()
        scope = null
        super.onStop()
    }

    private fun refreshApply(apply: Button) {
        val active = EngineStatus.state.value.let { it is BlockingState.Active || it is BlockingState.Starting }
        apply.visibility = if (SettingsChanges.needsRestart(current, original, active)) View.VISIBLE else View.GONE
    }

    private fun applyAndRestart(apply: Button) {
        apply.isEnabled = false
        scope?.launch {
            stopService(Intent(this@SettingsActivity, BlockerVpnService::class.java))
            // Event-driven wait: no timer or polling. The service publishes Idle after its workers stop.
            EngineStatus.state.first { it is BlockingState.Idle }
            val consent = VpnService.prepare(this@SettingsActivity)
            if (consent != null) {
                startActivityForResult(consent, REQUEST_CONSENT)
            } else {
                startForegroundService(Intent(this@SettingsActivity, BlockerVpnService::class.java))
            }
            original = current
            refreshApply(apply)
            apply.isEnabled = true
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CONSENT && resultCode == RESULT_OK) {
            startForegroundService(Intent(this, BlockerVpnService::class.java))
            original = current
            findViewById<Button>(R.id.applyRestartButton).visibility = View.GONE
        }
    }

    private fun snapshot(): SettingsChanges.Snapshot = SettingsChanges.Snapshot(
        safeSearch = AppSettings.safeSearchEnabled(this),
        strictResolver = AppSettings.strictResolverEnabled(this),
        fullTunnel = AppSettings.fullTunnelEnabled(this),
        blockQuic = AppSettings.blockQuicEnabled(this),
    )

    private companion object {
        const val REQUEST_CONSENT: Int = 42
    }
}
