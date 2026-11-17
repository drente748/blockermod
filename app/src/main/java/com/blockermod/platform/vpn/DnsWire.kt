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

    /** Result code: no error. */
    const val RCODE_NOERROR: Int = 0

    /** Result code: server failure (upstream unreachable or malformed response). */
    const val RCODE_SERVFAIL: Int = 2

    /** Result code: name error (the queried name does not exist). */
    const val RCODE_NXDOMAIN: Int = 3

    /** An upstream lookup result: the response code and the answer records. */
    class Answer(val rcode: Int, val records: List<DnsRecord>)

    /** Maximum number of compression pointer hops followed while resolving a name. */
    private const val MAX_POINTER_HOPS: Int = 10

    /** Maximum length of a single label in bytes. */
    private const val MAX_LABEL_LENGTH: Int = 63

    /** Record types whose RDATA starts with one or more domain names. */
    private const val TYPE_NS: Int = 2
    private const val TYPE_CNAME: Int = 5
    private const val TYPE_SOA: Int = 6
    private const val TYPE_PTR: Int = 12
    private const val TYPE_MX: Int = 15
    private const val TYPE_OPT: Int = 41

    /** Upper bound on parsed answer records: a 16-bit count must not size an allocation (B8). */
    internal const val MAX_ANSWERS: Int = 128

    /** EDNS(0) UDP payload size: fits in a 1280-byte IPv6 frame without fragmentation. */
    const val EDNS_PAYLOAD_SIZE: Int = 1232

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
        writeU16(out, 1) // QDCOUNT
        writeU16(out, 0) // ANCOUNT
        writeU16(out, 0) // NSCOUNT
        writeU16(out, 1) // ARCOUNT: one OPT pseudo-RR (RFC 6891)
        out.write(encodeName(name))
        writeU16(out, type)
        writeU16(out, 1) // class IN

        // EDNS(0): advertise a 1232-byte UDP payload, which fits in a 1280-byte IPv6 frame and
        // avoids IP fragmentation (a leading cause of DNS retries over TCP and battery drain).
        out.write(0) // root name
        writeU16(out, TYPE_OPT)
        writeU16(out, EDNS_PAYLOAD_SIZE)
        writeU32(out, 0) // extended rcode + flags
        writeU16(out, 0) // RDLEN

        return out.toByteArray()
    }

    /**
     * Reads the response code from a DNS response header.
     */
    fun responseRcode(packet: ByteArray): Int =
        if (packet.size >= HEADER_SIZE) readU16(packet, 2) and 0x0F else RCODE_SERVFAIL

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
        if (answerCount > MAX_ANSWERS) return emptyList()

        var offset = HEADER_SIZE
        repeat(questionCount) {
            offset = skipName(packet, offset) ?: return emptyList()
            if (offset + 4 > packet.size) return emptyList()
            offset += 4
        }

        val records = ArrayList<DnsRecord>(answerCount.coerceAtMost(MAX_ANSWERS))

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

            val data = normalizeRdata(packet, cursor, dataLength, type) ?: return emptyList()
            records.add(DnsRecord(owner.text, type, klass, ttl, data))
            cursor += dataLength
            offset = cursor
        }

        return records
    }

    /**
     * Rewrites compression pointers inside name-bearing RDATA as plain names, so the record can be
     * copied into a new response without pointing at the wrong offsets. A pointer in the upstream
     * message is relative to that message, not to the response we build, so copying it verbatim
     * would corrupt the answer. Other RDATA (A, AAAA, TXT, ...) contains no pointers and is copied as
     * is. Malformed name-bearing records are rejected.
     */
    private fun normalizeRdata(packet: ByteArray, start: Int, length: Int, type: Int): ByteArray? {
        val end = start + length
        return when (type) {
            TYPE_CNAME, TYPE_NS, TYPE_PTR -> {
                val name = readName(packet, start) ?: return null
                if (name.nextOffset > end) return null
                encodeName(name.text)
            }
            TYPE_MX -> {
                if (length < 3) return null
                val name = readName(packet, start + 2) ?: return null
                if (name.nextOffset > end) return null
                packet.copyOfRange(start, start + 2) + encodeName(name.text)
            }
            TYPE_SOA -> {
                val primary = readName(packet, start) ?: return null
                val admin = readName(packet, primary.nextOffset) ?: return null
                if (admin.nextOffset + 20 > end) return null
                encodeName(primary.text) + encodeName(admin.text) +
                    packet.copyOfRange(admin.nextOffset, end)
            }
            else -> packet.copyOfRange(start, end)
        }
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
