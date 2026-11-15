package com.blockermod.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import com.blockermod.R

/**
 * The setup guide: the two system steps the user has to do by hand.
 */
class OnboardingActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_onboarding)

        findViewById<Button>(R.id.closeButton).setOnClickListener { finish() }
    }
}
