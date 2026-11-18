package com.blockermod.ui

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import com.blockermod.R
import com.blockermod.core.BlockingState
import com.blockermod.platform.vpn.BlockerVpnService
import com.blockermod.platform.vpn.EngineStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The single screen of the application.
 *
 * It starts and stops the tunnel, shows the state of the engine and the number of domains blocked
 * today, and opens the settings and the setup guide.
 */
class MainActivity : Activity() {

    private var scope: CoroutineScope? = null

    private lateinit var stateLabel: TextView
    private lateinit var counterLabel: TextView
    private lateinit var warningLabel: TextView
    private lateinit var toggleButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        stateLabel = findViewById(R.id.stateLabel)
        counterLabel = findViewById(R.id.counterLabel)
        warningLabel = findViewById(R.id.warningLabel)
        toggleButton = findViewById(R.id.toggleButton)

        toggleButton.setOnClickListener { onToggle() }
        findViewById<Button>(R.id.settingsButton).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
        findViewById<Button>(R.id.onboardingButton).setOnClickListener {
            startActivity(Intent(this, OnboardingActivity::class.java))
        }
        requestNotificationPermissionIfNeeded()
    }

    /** The foreground-service notification is invisible on Android 13+ without this grant. */
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_NOTIFICATIONS,
            )
        }
    }

    override fun onStart() {
        super.onStart()
        scope = CoroutineScope(Dispatchers.Main + SupervisorJob()).also { active ->
            active.launch { EngineStatus.state.collect { render(it) } }
            active.launch {
                EngineStatus.privateDns.collect { warningLabel.visibility =
                    if (it) View.VISIBLE else View.GONE }
            }
            active.launch { EngineStatus.blockedTodayFlow.collect { renderCounter(it) } }
        }
        refreshCounter()
    }

    override fun onStop() {
        scope?.cancel()
        scope = null
        super.onStop()
    }

    private fun render(state: BlockingState) {
        when (state) {
            is BlockingState.Idle -> stateLabel.setText(R.string.state_idle)
            is BlockingState.Starting -> stateLabel.setText(R.string.state_starting)
            is BlockingState.Active -> stateLabel.setText(R.string.state_active)
            is BlockingState.Error -> stateLabel.text = getString(R.string.state_error, state.message)
        }

        val running = state is BlockingState.Active || state is BlockingState.Starting
        toggleButton.setText(if (running) R.string.stop_protection else R.string.start_protection)
    }

    private fun refreshCounter() {
        renderCounter(EngineStatus.blockedToday())
    }

    private fun renderCounter(blocked: Long) {
        counterLabel.text = if (blocked == 0L) {
            getString(R.string.blocked_today_zero)
        } else {
            resources.getQuantityString(R.plurals.blocked_today, blocked.toInt(), blocked.toInt())
        }
    }

    private fun onToggle() {
        try {
            onToggleInternal()
        } catch (exception: Exception) {
            warningLabel.visibility = View.VISIBLE
            warningLabel.text = getString(R.string.state_error, exception.message ?: exception.javaClass.simpleName)
        }
    }

    private fun onToggleInternal() {
        val state = EngineStatus.state.value
        if (state is BlockingState.Active || state is BlockingState.Starting) {
            stopService(Intent(this, BlockerVpnService::class.java))
            return
        }

        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQUEST_CONSENT)
            return
        }

        startService(Intent(this, BlockerVpnService::class.java))
    }

    @Deprecated("the activity result api is the only one available without the activity library")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQUEST_CONSENT && resultCode == RESULT_OK) {
            startService(Intent(this, BlockerVpnService::class.java))
        }
    }

    private companion object {
        const val REQUEST_CONSENT: Int = 4711
        const val REQUEST_NOTIFICATIONS: Int = 4712
    }
}
