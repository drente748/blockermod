package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsRecord
import java.io.ByteArrayOutputStream

/**
 * Minimal DNS wire helpers used by the tunnel: name encoding, query building and answer parsing.
 *
 * The shared codec in the core module parses queries and builds responses; the reverse direction,
 * reading the answers of an upstream server, is covered here until the core codec grows it.
 */
internal object DnsWire {

    /** Size of the DNS header in bytes. */
    private const val HEADER_SIZE: Int = 12

    /** Maximum number of compression pointer hops followed while resolving a name. */
    private const val MAX_POINTER_HOPS: Int = 10

    /** Maximum length of a single label in bytes. */
    private const val MAX_LABEL_LENGTH: Int = 63

    /**
     * Encodes a domain name in wire format: length prefixed labels followed by the root label.
     */
    fun encodeName(name: String): ByteArray {
        val out = ByteArrayOutputStream()

        for (label in name.split('.')) {
            if (label.isEmpty()) continue
            val bytes = label.toByteArray(Charsets.US_ASCII)
            val size = minOf(bytes.size, MAX_LABEL_LENGTH)
            out.write(size)
            out.write(bytes, 0, size)
        }
        out.write(0)

        return out.toByteArray()
    }

    /**
     * Builds a standard query for the given name and record type.
     */
    fun buildQuery(id: Int, name: String, type: Int): ByteArray {
        val out = ByteArrayOutputStream()

        writeU16(out, id)
        writeU16(out, 0x0100)
        writeU16(out, 1)
        writeU16(out, 0)
        writeU16(out, 0)
        writeU16(out, 0)
        out.write(encodeName(name))
        writeU16(out, type)
        writeU16(out, 1)

        return out.toByteArray()
    }

    /**
     * Parses the answer records of a DNS response.
     *
     * Returns an empty list when the response is malformed; records keep the raw record data so a
     * CNAME can be forwarded untouched.
     */
    fun parseAnswers(packet: ByteArray): List<DnsRecord> {
        if (packet.size < HEADER_SIZE) return emptyList()

        val questionCount = readU16(packet, 4)
        val answerCount = readU16(packet, 6)

        var offset = HEADER_SIZE
        repeat(questionCount) {
            offset = skipName(packet, offset) ?: return emptyList()
            if (offset + 4 > packet.size) return emptyList()
            offset += 4
        }

        val records = ArrayList<DnsRecord>(answerCount)

        repeat(answerCount) {
            val owner = readName(packet, offset) ?: return emptyList()
            var cursor = owner.nextOffset
            if (cursor + 10 > packet.size) return emptyList()

            val type = readU16(packet, cursor)
            val klass = readU16(packet, cursor + 2)
            val ttl = readU32(packet, cursor + 4)
            val dataLength = readU16(packet, cursor + 8)
            cursor += 10

            if (cursor + dataLength > packet.size) return emptyList()

            records.add(DnsRecord(owner.text, type, klass, ttl, packet.copyOfRange(cursor, cursor + dataLength)))
            cursor += dataLength
            offset = cursor
        }

        return records
    }

    /**
     * Reads a possibly compressed name and returns its text with the offset that follows it.
     */
    fun readName(packet: ByteArray, startOffset: Int): NameResult? {
        val labels = StringBuilder()
        var offset = startOffset
        var nextOffset = -1
        var hops = 0

        while (true) {
            if (offset >= packet.size) return null
            val length = packet[offset].toInt() and 0xFF

            if (length == 0) {
                offset++
                if (nextOffset < 0) nextOffset = offset
                break
            }

            if (length and 0xC0 == 0xC0) {
                if (offset + 1 >= packet.size) return null
                val pointer = ((length and 0x3F) shl 8) or (packet[offset + 1].toInt() and 0xFF)
                if (nextOffset < 0) nextOffset = offset + 2
                if (++hops > MAX_POINTER_HOPS) return null
                if (pointer >= packet.size) return null
                offset = pointer
                continue
            }

            if (length and 0xC0 != 0) return null
            if (offset + 1 + length > packet.size) return null

            if (labels.isNotEmpty()) labels.append('.')
            labels.append(String(packet, offset + 1, length, Charsets.ISO_8859_1))
            offset += 1 + length
        }

        return NameResult(labels.toString(), nextOffset)
    }

    private fun skipName(packet: ByteArray, startOffset: Int): Int? = readName(packet, startOffset)?.nextOffset

    /**
     * A decoded name and the offset that follows it in the message.
     */
    internal class NameResult(val text: String, val nextOffset: Int)

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)

    private fun readU32(packet: ByteArray, offset: Int): Long =
        ((packet[offset].toLong() and 0xFF) shl 24) or
            ((packet[offset + 1].toLong() and 0xFF) shl 16) or
            ((packet[offset + 2].toLong() and 0xFF) shl 8) or
            (packet[offset + 3].toLong() and 0xFF)

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }
}
