package com.blockermod.platform.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import com.blockermod.R
import com.blockermod.core.BlockReason
import com.blockermod.core.BlockingState
import com.blockermod.core.matcher.InMemoryDomainMatcher
import com.blockermod.core.lockout.NoOpLockoutPolicy
import com.blockermod.core.policy.PolicyEngine
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The DNS only tunnel that enforces the blocking policy.
 *
 * The tunnel captures nothing but the virtual DNS address: the route is a single host route, every
 * other packet of the device keeps using the normal network. Queries are answered from the policy
 * engine, and allowed queries are forwarded to the DNS servers of the active network.
 */
class BlockerVpnService : VpnService() {

    private var tunnel: VpnTunnel? = null
    private var responder: DnsResponder? = null
    private var tunnelDescriptor: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var blocklist: AssetRules.BlocklistHandle? = null
    private var upstreamResolver: UpstreamResolver? = null
    private var fullTunnel: Boolean = false
    private var tunnelOutput: java.io.OutputStream? = null
    private val tunnelOutputLock = Any()

    private val upstreamServers = CopyOnWriteArrayList<InetAddress>()
    private val physicalNetworks = CopyOnWriteArrayList<Network>()

    @Volatile
    private var physicalNetwork: Network? = null

    @Volatile
    private var privateDnsActive: Boolean = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        try {
            StrictResolverIps.initialize(this)
            StrictResolverIps.setEnabled(AppSettings.strictResolverEnabled(this))
        } catch (exception: Exception) {
            Log.e(TAG, "the strict resolver list could not be loaded", exception)
        }
        try {
            registerNetworkCallback()
        } catch (exception: Exception) {
            Log.e(TAG, "the network callback could not be registered", exception)
        }
        EngineStatus.publish(BlockingState.Idle)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (tunnel != null) {
            EngineStatus.publish(BlockingState.Active)
            return START_STICKY
        }
        try {
            EngineStatus.publish(BlockingState.Starting)
            startForeground(NOTIFICATION_ID, buildNotification())
            fullTunnel = AppSettings.fullTunnelEnabled(this)

            val descriptor = establishTunnel()
            if (descriptor == null) {
                EngineStatus.publish(BlockingState.Error("the tunnel could not be established"))
                stopSelf()
                return START_NOT_STICKY
            }

            tunnelDescriptor = descriptor

            val created = createResponder()
            responder = created

            val tcpRelay = if (fullTunnel) {
                TcpRelay(
                    protectSocket = { protect(it) },
                    writePacket = { packet -> writeTunnelPacket(packet) },
                    dohHosts = created.bypassMatcher(),
                    onDohBlocked = { EngineStatus.recordBlocked() },
                    dnsPolicy = { framed -> created.resolveTcp(framed) },
                )
            } else null
            val udpRelay = if (fullTunnel) {
                UdpRelay(
                    protectSocket = { protect(it) },
                    writePacket = { packet -> writeTunnelPacket(packet) },
                )
            } else null

            val output = FileOutputStream(descriptor.fileDescriptor)
            tunnelOutput = output
            val started = VpnTunnel(
                input = FileInputStream(descriptor.fileDescriptor),
                output = output,
                responder = created,
                fullTunnel = fullTunnel,
                tcpRelay = tcpRelay,
                udpRelay = udpRelay,
            )
            started.start()
            tunnel = started
            EngineStatus.publish(BlockingState.Active)

            return START_STICKY
        } catch (exception: Exception) {
            closeQuietly(tunnelDescriptor)
            tunnelDescriptor = null

            val message = exception.message ?: exception.javaClass.simpleName
            Log.e(TAG, "the tunnel could not be started", exception)
            EngineStatus.publish(BlockingState.Error(message))
            stopSelf()
            return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        stopTunnel()
        // Without stopSelf the foreground notification keeps claiming protection is active.
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        unregisterNetworkCallback()
        upstreamResolver?.close()
        upstreamResolver = null
        blocklist?.close()
        blocklist = null
        super.onDestroy()
    }

    private fun establishTunnel(): ParcelFileDescriptor? {
        val builder = Builder()
            .addAddress(TUN_ADDRESS, TUN_PREFIX_LENGTH)
            .addDnsServer(VIRTUAL_DNS_ADDRESS)
            .addRoute(VIRTUAL_DNS_ADDRESS, DNS_ROUTE_PREFIX_LENGTH)
            .setBlocking(true)
            .setMtu(MTU)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        for (route in StrictResolverIps.routes()) {
            builder.addRoute(route, DNS_ROUTE_PREFIX_LENGTH)
        }

        if (fullTunnel) {
            // Full capture: every IPv4 packet enters the tunnel and is relayed or filtered.
            builder.addRoute("0.0.0.0", 0)
            // Android blocks an address family that has no address/route/DNS server in the builder.
            // Let IPv6 fall through to the underlying network so dual-stack devices keep working;
            // IPv6 is not filtered by this engine (documented limitation).
            builder.allowFamily(OsConstants.AF_INET6)
        }

        // Pin the tunnel to the single physical network we bind upstream sockets to. Without this
        // the system may keep Wi-Fi and mobile data up at the same time to satisfy the VPN, which
        // costs battery and can change the upstream server under us mid-lookup.
        physicalNetwork?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
        builder.setSession(getString(R.string.app_name))

        return try {
            builder.establish()
        } catch (exception: IllegalStateException) {
            null
        }
    }

    /** Writes a packet directly to the tunnel from a relay thread. */
    private fun writeTunnelPacket(packet: ByteArray) {
        synchronized(tunnelOutputLock) {
            try {
                tunnelOutput?.write(packet)
                tunnelOutput?.flush()
            } catch (exception: IOException) {
                // the tunnel is closing
            }
        }
    }

    private fun closeQuietly(descriptor: ParcelFileDescriptor?) {
        try {
            descriptor?.close()
        } catch (exception: IOException) {
            // the descriptor is already closed
        }
    }

    private fun stopTunnel() {
        val running = tunnel ?: return
        running.stop()
        running.awaitStopped(STOP_TIMEOUT_MILLIS)
        tunnel = null
        logRecordedDecisions()
        privateDnsActive = false
        EngineStatus.publishPrivateDns(false)
        EngineStatus.publish(BlockingState.Idle)

        try {
            tunnelDescriptor?.close()
        } catch (exception: IOException) {
            // the descriptor is already closed
        }
        tunnelDescriptor = null
        synchronized(tunnelOutputLock) { tunnelOutput = null }
    }

    /**
     * Prints the decisions recorded by the debug mode.
     *
     * The formatting happens here and never in the packet path.
     */
    private fun logRecordedDecisions() {
        val recorded = responder?.decisions?.drain() ?: return
        for (decision in recorded) {
            Log.d(TAG, "decision: $decision")
        }
    }

    private fun createResponder(): DnsResponder {
        val cache = DnsCache()
        val resolver = UpstreamResolver(
            socketBinder = { socket -> bindToPhysicalNetwork(socket) },
            upstreamServers = { upstreamServers.toList() },
            activeNetwork = { physicalNetwork },
        )
        upstreamResolver = resolver

        return DnsResponder(
            policy = createPolicyEngine(),
            upstream = resolver,
            cache = cache,
            logOnly = LOG_ONLY_MODE,
            onBlocked = { EngineStatus.recordBlocked() },
        )
    }

    private fun createPolicyEngine(): PolicyEngine {
        // Fail closed: without the blocklist the engine would allow everything and report Active.
        val handle = AssetRules.openBlocklist(this)
        blocklist = handle

        val safeSearchTable = if (AppSettings.safeSearchEnabled(this)) {
            try {
                AssetRules.readSafeSearchTable(this)
            } catch (exception: IOException) {
                Log.e(TAG, "the safe search table could not be read", exception)
                EmptySafeSearchTable
            }
        } else {
            EmptySafeSearchTable
        }

        val allowlist = try {
            AssetRules.readAllowlist(this)
        } catch (exception: IOException) {
            Log.e(TAG, "the allowlist could not be read", exception)
            InMemoryDomainMatcher(emptySet())
        }

        // Fail closed for the other rule sources too: no engine with a missing blocklist.
        val bypassBlocklist = AssetRules.openMatcher(this, AssetRules.BYPASS_ASSET)
        val unsupportedBlocklist = AssetRules.openMatcher(this, AssetRules.UNSUPPORTED_ASSET)

        return PolicyEngine(
            allowlist = allowlist,
            adultBlocklist = handle.matcher,
            bypassBlocklist = bypassBlocklist,
            unsupportedEngineBlocklist = unsupportedBlocklist,
            safeSearchTable = safeSearchTable,
            lockoutPolicy = NoOpLockoutPolicy(),
        )
    }

    private fun bindToPhysicalNetwork(socket: DatagramSocket): Boolean {
        val network = physicalNetwork ?: return false
        return try {
            network.bindSocket(socket)
            true
        } catch (exception: IOException) {
            false
        }
    }

    /**
     * Keeps the VPN's underlying network in sync with the physical network we bind upstream sockets
     * to. A stale pin can make Android keep both Wi-Fi and mobile up, and can route the upstream
     * socket through a dead path after a handover.
     */
    private fun applyUnderlyingNetwork(network: Network?) {
        try {
            if (network != null) {
                setUnderlyingNetworks(arrayOf(network))
            } else {
                // Null restores the system default network selection.
                setUnderlyingNetworks(null)
            }
        } catch (exception: Exception) {
            // No established tunnel yet (or the system rejected the pin): harmless, the next
            // onAvailable/onLost will retry. Must not crash the network callback thread.
            Log.w(TAG, "could not update the underlying network", exception)
        }
    }

    private fun registerNetworkCallback() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (isTunnel(network)) return
                physicalNetworks.addIfAbsent(network)
                physicalNetwork = network
                applyUnderlyingNetwork(network)
                manager.getLinkProperties(network)?.let { updateLinkProperties(it) }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                if (isTunnel(network)) return
                physicalNetworks.addIfAbsent(network)
                physicalNetwork = network
                updateLinkProperties(linkProperties)
            }

            override fun onLost(network: Network) {
                physicalNetworks.remove(network)
                if (network != physicalNetwork) return

                val remaining = physicalNetworks.firstOrNull()
                physicalNetwork = remaining
                applyUnderlyingNetwork(remaining)
                if (remaining == null) {
                    upstreamServers.clear()
                } else {
                    manager.getLinkProperties(remaining)?.let { updateLinkProperties(it) }
                }
            }
        }

        // The default network becomes the tunnel itself once it is established, and its only DNS
        // server is our virtual address: resolving through it would loop straight back into the
        // tunnel. Ask for a network that is explicitly not a VPN.
        manager.registerNetworkCallback(PHYSICAL_NETWORK_REQUEST, callback)
        networkCallback = callback
    }

    private fun isTunnel(network: Network): Boolean =
        getSystemService(ConnectivityManager::class.java)
            ?.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    private fun unregisterNetworkCallback() {
        val manager = getSystemService(ConnectivityManager::class.java)
        val callback = networkCallback ?: return
        manager.unregisterNetworkCallback(callback)
        networkCallback = null
        physicalNetworks.clear()
        physicalNetwork = null
        upstreamServers.clear()
    }

    private fun updateLinkProperties(linkProperties: LinkProperties) {
        val servers = linkProperties.dnsServers.filterNot { it.hostAddress == VIRTUAL_DNS_ADDRESS }
        if (servers.isNotEmpty() && servers.toList() != upstreamServers.toList()) {
            upstreamServers.clear()
            upstreamServers.addAll(servers)
            // Answers learned from the old network's resolvers are stale after a handover.
            responder?.clearCache()
        }

        privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            linkProperties.isPrivateDnsActive
        } else {
            false
        }
        EngineStatus.publishPrivateDns(privateDnsActive)
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.engine_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, com.blockermod.ui.MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.engine_notification_text))
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(openApp)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private companion object {
        /** Tag used for the lifecycle logs. */
        const val TAG: String = "BlockerMod"

        /** Address of the tunnel interface. */
        const val TUN_ADDRESS: String = "10.111.222.1"

        /** Prefix length of the tunnel interface address. */
        const val TUN_PREFIX_LENGTH: Int = 32

        /** Address of the virtual DNS server inside the tunnel. */
        const val VIRTUAL_DNS_ADDRESS: String = "10.111.222.3"

        /** Prefix length of the single route the tunnel captures. */
        const val DNS_ROUTE_PREFIX_LENGTH: Int = 32

        /** Maximum transmission unit of the tunnel interface. */
        const val MTU: Int = 1500

        /** Identifier of the foreground notification. */
        const val NOTIFICATION_ID: Int = 4711

        /** Identifier of the notification channel. */
        const val NOTIFICATION_CHANNEL_ID: String = "blockermod_engine"

        /** Time given to the tunnel to stop, in milliseconds. */
        const val STOP_TIMEOUT_MILLIS: Long = 2000L

        /** Debug mode: resolve everything, record the decisions, and block nothing. */
        const val LOG_ONLY_MODE: Boolean = false

        /** Networks that are not a VPN: only those carry the real DNS servers. */
        private val PHYSICAL_NETWORK_REQUEST: NetworkRequest =
            NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
    }
}
