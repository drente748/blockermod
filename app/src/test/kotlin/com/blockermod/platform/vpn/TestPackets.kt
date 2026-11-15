package com.blockermod.platform.vpn

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Helpers shared by the tunnel tests: packet builders and a stream that blocks until it is closed.
 */
internal object TestPackets {

    /**
     * Builds an IPv4 and UDP packet carrying the given payload.
     */
    fun ipv4Udp(
        payload: ByteArray,
        sourcePort: Int = 40000,
        destinationPort: Int = 53,
        sourceAddress: Int = 0x0A000001,
        destinationAddress: Int = 0x0A000003,
    ): ByteArray {
        val udpLength = 8 + payload.size
        val packet = ByteArray(20 + udpLength)

        packet[0] = 0x45
        writeU16(packet, 2, packet.size)
        writeU16(packet, 4, 0x1234)
        writeU16(packet, 6, 0x4000)
        packet[8] = 64
        packet[9] = 17
        writeU32(packet, 12, sourceAddress)
        writeU32(packet, 16, destinationAddress)
        writeU16(packet, 10, checksum(packet, 0, 20))

        writeU16(packet, 20, sourcePort)
        writeU16(packet, 22, destinationPort)
        writeU16(packet, 24, udpLength)
        writeU16(packet, 26, 0)
        payload.copyInto(packet, 28)

        writeU16(packet, 26, udpChecksum(packet, 20, udpLength))

        return packet
    }

    /**
     * Builds an IPv4 and TCP packet addressed to the DNS port.
     */
    fun ipv4Tcp(destinationPort: Int = 53): ByteArray {
        val packet = ByteArray(40)
        packet[0] = 0x45
        writeU16(packet, 2, packet.size)
        writeU16(packet, 4, 0x1234)
        packet[8] = 64
        packet[9] = 6
        writeU32(packet, 12, 0x0A000001)
        writeU32(packet, 16, 0x0A000003)
        writeU16(packet, 10, checksum(packet, 0, 20))
        writeU16(packet, 20, 40000)
        writeU16(packet, 22, destinationPort)
        return packet
    }

    fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var index = offset
        val end = offset + length

        while (index + 1 < end) {
            sum += ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) {
            sum += (data[index].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }

        return (sum and 0xFFFF) xor 0xFFFF
    }

    fun udpChecksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        sum += ((packet[12].toInt() and 0xFF) shl 8) or (packet[13].toInt() and 0xFF)
        sum += ((packet[14].toInt() and 0xFF) shl 8) or (packet[15].toInt() and 0xFF)
        sum += ((packet[16].toInt() and 0xFF) shl 8) or (packet[17].toInt() and 0xFF)
        sum += packet[9].toInt() and 0xFF
        sum += length

        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += ((packet[index].toInt() and 0xFF) shl 8) or (packet[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) {
            sum += (packet[index].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }

        val folded = (sum and 0xFFFF) xor 0xFFFF
        return if (folded == 0) 0xFFFF else folded
    }

    fun writeU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 1] = (value and 0xFF).toByte()
    }

    fun writeU32(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 24) and 0xFF).toByte()
        packet[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        packet[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 3] = (value and 0xFF).toByte()
    }
}

/**
 * Input stream that hands over the packets it was given and blocks once they are consumed.
 */
internal class BlockingInputStream : InputStream() {

    private val packets = LinkedBlockingQueue<ByteArray>()
    private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

    fun offer(packet: ByteArray) {
        packets.put(packet)
    }

    override fun read(): Int {
        val packet = take() ?: return -1
        return packet[0].toInt() and 0xFF
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        val packet = take() ?: return -1
        val size = minOf(length, packet.size)
        packet.copyInto(buffer, offset, 0, size)
        return size
    }

    override fun close() {
        closed.set(true)
        packets.offer(ByteArray(0))
    }

    private fun take(): ByteArray? {
        if (closed.get()) return null
        return try {
            packets.poll(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        } catch (exception: InterruptedException) {
            null
        }
    }

    private companion object {
        const val TIMEOUT_MILLIS: Long = 50L
    }
}

/**
 * Output stream that keeps the written bytes and signals the writers.
 */
internal class SignallingOutputStream : ByteArrayOutputStream() {

    private val signal = CountDownLatch(1)

    override fun write(byteArray: ByteArray, offset: Int, length: Int) {
        super.write(byteArray, offset, length)
        signal.countDown()
    }

    fun awaitWritten(timeoutMillis: Long): Boolean = signal.await(timeoutMillis, TimeUnit.MILLISECONDS)
}
