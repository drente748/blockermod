package com.blockermod.core.vpn

import android.net.VpnService

/**
 * Host process of the blocking engine.
 *
 * Phase 0 (scaffold): the service exists so the entry point, the foreground service type and the
 * VPN permission wiring are settled. The tunnel, the resolver and the rule matcher arrive in
 * phase 1 (see PROGRESS.md).
 */
class BlockerVpnService : VpnService()
