package com.blockermod.platform.vpn

import com.blockermod.core.net.Ipv4UdpPacket
import java.net.DatagramSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Atomic flow creation and packet-driven idle reaping (C1). */
class UdpRelayTest {

    @Test
    fun `concurrent first datagrams create exactly one socket and one thread`() {
        val protected = AtomicInteger(0)
        val relay = UdpRelay(
            protectSocket = { protected.incrementAndGet(); true },
            writePacket = {},
        )
        val start = CountDownLatch(1)
        val workers = (1..8).map {
            Thread {
                start.await()
                relay.handle(datagram())
            }.apply { isDaemon = true; start() }
        }
        try {
            start.countDown()
            workers.forEach { it.join(3_000) }

            assertEquals(1, protected.get(), "only one socket may be created for a new flow")
            assertEquals(1, relay.flowCount())
        } finally {
            relay.closeAll()
        }
        assertEquals(0, relay.flowCount(), "closeAll must remove every flow")
    }

    @Test
    fun `idle reaping skips the active flow`() {
        var now = 0L
        val relay = UdpRelay(
            protectSocket = { true },
            writePacket = {},
            idleTimeoutMillis = 1_000L,
            nowMillis = { now },
        )
        try {
            relay.handle(datagram(sourcePort = 40000))
            now = 6_000L
            // The gate opens after 5s: the first flow is idle and must be reaped.
            relay.handle(datagram(sourcePort = 40001))
            assertEquals(1, relay.flowCount())

            // Refresh the active flow at the CURRENT time right before the next gate opens.
            now = 12_000L
            relay.handle(datagram(sourcePort = 40001))
            relay.handle(datagram(sourcePort = 40002))

            assertEquals(2, relay.flowCount(), "the just-active flow must not be reaped")
        } finally {
            relay.closeAll()
        }
    }

    @Test
    fun `the flow table stays capped`() {
        val relay = UdpRelay(protectSocket = { true }, writePacket = {})
        try {
            repeat(200) { relay.handle(datagram(sourcePort = 40_000 + it)) }
            assertEquals(128, relay.flowCount())
        } finally {
            relay.closeAll()
        }
    }

    private fun datagram(sourcePort: Int = 40_000) = Ipv4UdpPacket(
        sourceAddress = 0x0A000001,
        destinationAddress = 0x0A000003,
        sourcePort = sourcePort,
        destinationPort = 53,
        payload = byteArrayOf(1, 2, 3),
        identification = 1,
        ttl = 64,
        ipHeaderLength = 20,
    )
}
