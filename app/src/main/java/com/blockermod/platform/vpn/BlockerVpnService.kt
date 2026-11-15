package com.blockermod.platform.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
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

    private val upstreamServers = CopyOnWriteArrayList<InetAddress>()

    @Volatile
    private var physicalNetwork: Network? = null

    @Volatile
    private var privateDnsActive: Boolean = false

    /**
     * True when the device forces private DNS, which bypasses the DNS based blocking.
     */
    fun isPrivateDnsActive(): Boolean = privateDnsActive

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        try {
            registerNetworkCallback()
        } catch (exception: Exception) {
            Log.e(TAG, "the network callback could not be registered", exception)
        }
        EngineStatus.publish(BlockingState.Idle)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            EngineStatus.publish(BlockingState.Starting)
            startForeground(NOTIFICATION_ID, buildNotification())

            val descriptor = establishTunnel()
            if (descriptor == null) {
                EngineStatus.publish(BlockingState.Error("the tunnel could not be established"))
                stopSelf()
                return START_NOT_STICKY
            }

            tunnelDescriptor = descriptor

            val created = createResponder()
            responder = created

            val started = VpnTunnel(
                input = FileInputStream(descriptor.fileDescriptor),
                output = FileOutputStream(descriptor.fileDescriptor),
                responder = created,
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
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        unregisterNetworkCallback()
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

        return try {
            builder.establish()
        } catch (exception: IllegalStateException) {
            null
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
        EngineStatus.publish(BlockingState.Idle)

        try {
            tunnelDescriptor?.close()
        } catch (exception: IOException) {
            // the descriptor is already closed
        }
        tunnelDescriptor = null
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
            cache = cache,
            socketBinder = { socket -> bindToPhysicalNetwork(socket) },
            upstreamServers = { upstreamServers.toList() },
        )

        return DnsResponder(
            policy = createPolicyEngine(),
            upstream = resolver,
            logOnly = LOG_ONLY_MODE,
            onBlocked = { EngineStatus.recordBlocked() },
        )
    }

    private fun createPolicyEngine(): PolicyEngine {
        val handle = try {
            AssetRules.openBlocklist(this)
        } catch (exception: IOException) {
            Log.e(TAG, "the blocklist could not be opened", exception)
            null
        }
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

        return PolicyEngine(
            allowlist = InMemoryDomainMatcher(emptySet()),
            adultBlocklist = handle?.matcher ?: InMemoryDomainMatcher(emptySet()),
            bypassBlocklist = InMemoryDomainMatcher(emptySet()),
            unsupportedEngineBlocklist = InMemoryDomainMatcher(emptySet()),
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

    private fun registerNetworkCallback() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                physicalNetwork = network
                manager.getLinkProperties(network)?.let { updateLinkProperties(it) }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                physicalNetwork = network
                updateLinkProperties(linkProperties)
            }
        }

        manager.registerDefaultNetworkCallback(callback)
        networkCallback = callback
    }

    private fun unregisterNetworkCallback() {
        val manager = getSystemService(ConnectivityManager::class.java)
        val callback = networkCallback ?: return
        manager.unregisterNetworkCallback(callback)
        networkCallback = null
    }

    private fun updateLinkProperties(linkProperties: LinkProperties) {
        upstreamServers.clear()
        linkProperties.dnsServers.forEach { server -> upstreamServers.add(server) }

        privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            linkProperties.isPrivateDnsActive
        } else {
            false
        }
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

    private fun buildNotification(): Notification =
        NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.engine_notification_text))
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

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
    }
}
