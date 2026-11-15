package com.blockermod.core.dns

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * DNS record type codes used across the codec.
 */
object DnsTypes {
    /** IPv4 host address record. */
    const val A: Int = 1

    /** Authoritative name server record. */
    const val NS: Int = 2

    /** Canonical name record. */
    const val CNAME: Int = 5

    /** Start of authority record. */
    const val SOA: Int = 6

    /** Pointer record. */
    const val PTR: Int = 12

    /** Mail exchange record. */
    const val MX: Int = 15

    /** Text record. */
    const val TXT: Int = 16

    /** IPv6 host address record. */
    const val AAAA: Int = 28

    /** EDNS pseudo record carrying the extended header. */
    const val OPT: Int = 41

    /** HTTPS service binding record. */
    const val HTTPS: Int = 65

    /** Query requesting any record type. */
    const val ANY: Int = 255
}

/**
 * Question section of a DNS query.
 *
 * @property name domain name decoded from the wire format; bytes are preserved one to one.
 * @property type requested record type, see [DnsTypes].
 * @property klass requested record class; 1 means IN (Internet).
 */
data class DnsQuestion(
    val name: String,
    val type: Int,
    val klass: Int,
)

/**
 * Minimal EDNS metadata parsed from an OPT record.
 *
 * @property payloadSize UDP payload size advertised by the client in the OPT class field.
 * @property optionCount number of EDNS options found inside the OPT record.
 */
class DnsEdns(
    val payloadSize: Int,
    val optionCount: Int,
)

/**
 * A parsed DNS query.
 *
 * @property id transaction identifier, copied verbatim into every response.
 * @property flags raw flags word of the query header.
 * @property question the single question carried by the query.
 * @property questionBytes raw bytes of the question section, echoed verbatim in responses.
 * @property edns EDNS metadata, or null when the query carries no OPT record.
 */
class DnsQuery(
    val id: Int,
    val flags: Int,
    val question: DnsQuestion,
    val questionBytes: ByteArray,
    val edns: DnsEdns?,
) {
    /** True when the query advertises EDNS. */
    val hasEdns: Boolean
        get() = edns != null
}

/**
 * A resource record to place in an answer section.
 *
 * @property name owner name of the record.
 * @property type record type, see [DnsTypes].
 * @property klass record class; 1 means IN (Internet).
 * @property ttlSeconds time to live in seconds.
 * @property data raw record data.
 */
class DnsRecord(
    val name: String,
    val type: Int,
    val klass: Int,
    val ttlSeconds: Long,
    val data: ByteArray,
)

/**
 * Pure DNS message codec: parses queries and builds responses.
 *
 * The codec never throws. Malformed input is reported as `null` by [parseQuery], and builders
 * always produce a well formed message for a valid query.
 */
object DnsCodec {

    /** Size of the DNS header in bytes. */
    private const val HEADER_SIZE: Int = 12

    /** Maximum number of compression pointer hops followed while resolving a name. */
    private const val MAX_POINTER_HOPS: Int = 10

    /** Maximum length of an encoded domain name in bytes. */
    private const val MAX_NAME_LENGTH: Int = 255

    /** Maximum length of a single label in bytes. */
    private const val MAX_LABEL_LENGTH: Int = 63

    /** Query bit of the flags word. */
    private const val FLAG_QR: Int = 0x8000

    /** Recursion desired bit of the flags word. */
    private const val FLAG_RD: Int = 0x0100

    /** Response code: no error. */
    private const val RCODE_NOERROR: Int = 0

    /** Response code: server failure. */
    private const val RCODE_SERVFAIL: Int = 2

    /** Response code: non existent domain. */
    private const val RCODE_NXDOMAIN: Int = 3

    /** The internet class. */
    private const val CLASS_IN: Int = 1

    /** UDP payload size advertised by generated responses. */
    private const val RESPONSE_UDP_PAYLOAD: Int = 1232

    /**
     * Parses a DNS query.
     *
     * Returns null for anything that is not a single question query with a well formed question
     * section. Compression pointers are resolved with a hop limit, and the EDNS section is parsed
     * leniently: a malformed additional section simply yields no EDNS metadata instead of an error.
     */
    fun parseQuery(packet: ByteArray): DnsQuery? {
        if (packet.size < HEADER_SIZE) return null

        val id = readU16(packet, 0)
        val flags = readU16(packet, 2)
        val questionCount = readU16(packet, 4)
        val additionalCount = readU16(packet, 10)

        if (flags and FLAG_QR != 0) return null
        if (questionCount != 1) return null

        val name = readName(packet, HEADER_SIZE) ?: return null
        var offset = name.nextOffset
        if (offset + 4 > packet.size) return null

        val type = readU16(packet, offset)
        val klass = readU16(packet, offset + 2)
        offset += 4

        val question = DnsQuestion(name.text, type, klass)
        val questionBytes = packet.copyOfRange(HEADER_SIZE, offset)
        val edns = parseEdns(packet, offset, additionalCount)

        return DnsQuery(id, flags, question, questionBytes, edns)
    }

    /**
     * Builds a response reporting that the requested name does not exist.
     */
    fun buildNxDomain(query: DnsQuery): ByteArray =
        buildResponse(query, RCODE_NXDOMAIN, emptyList())

    /**
     * Builds a successful response without any answer record (no data for this type).
     */
    fun buildNoData(query: DnsQuery): ByteArray =
        buildResponse(query, RCODE_NOERROR, emptyList())

    /**
     * Builds a response reporting a server failure.
     */
    fun buildServFail(query: DnsQuery): ByteArray =
        buildResponse(query, RCODE_SERVFAIL, emptyList())

    /**
     * Builds a successful response carrying the given answer records.
     */
    fun buildAnswer(query: DnsQuery, records: List<DnsRecord>): ByteArray =
        buildResponse(query, RCODE_NOERROR, records)

    private fun buildResponse(query: DnsQuery, rcode: Int, answers: List<DnsRecord>): ByteArray {
        val out = ByteArrayOutputStream()
        val flags = FLAG_QR or (query.flags and FLAG_RD) or (rcode and 0x0F)

        writeU16(out, query.id)
        writeU16(out, flags)
        writeU16(out, 1)
        writeU16(out, answers.size)
        writeU16(out, 0)
        writeU16(out, if (query.hasEdns) 1 else 0)

        out.write(query.questionBytes)

        for (record in answers) {
            writeName(out, record.name, query.question.name)
            writeU16(out, record.type)
            writeU16(out, record.klass)
            writeU32(out, record.ttlSeconds)
            writeU16(out, record.data.size)
            out.write(record.data)
        }

        if (query.hasEdns) {
            out.write(0)
            writeU16(out, DnsTypes.OPT)
            writeU16(out, RESPONSE_UDP_PAYLOAD)
            writeU32(out, 0)
            writeU16(out, 0)
        }

        return out.toByteArray()
    }

    private fun writeName(out: ByteArrayOutputStream, name: String, questionName: String) {
        if (name.equals(questionName, ignoreCase = true)) {
            out.write(0xC0)
            out.write(HEADER_SIZE)
            return
        }

        for (label in name.split('.')) {
            if (label.isEmpty()) continue
            val bytes = label.toByteArray(StandardCharsets.US_ASCII)
            val size = minOf(bytes.size, MAX_LABEL_LENGTH)
            out.write(size)
            out.write(bytes, 0, size)
        }
        out.write(0)
    }

    private fun parseEdns(packet: ByteArray, offset: Int, additionalCount: Int): DnsEdns? {
        var position = offset
        var remaining = additionalCount
        var edns: DnsEdns? = null

        while (remaining > 0) {
            if (position >= packet.size) break
            val name = readName(packet, position) ?: break
            var cursor = name.nextOffset
            if (cursor + 10 > packet.size) break

            val type = readU16(packet, cursor)
            val klass = readU16(packet, cursor + 2)
            val dataLength = readU16(packet, cursor + 8)
            cursor += 10
            if (cursor + dataLength > packet.size) break

            if (type == DnsTypes.OPT) {
                edns = DnsEdns(klass, countEdnsOptions(packet, cursor, dataLength))
            }

            cursor += dataLength
            position = cursor
            remaining--
        }

        return edns
    }

    private fun countEdnsOptions(packet: ByteArray, offset: Int, length: Int): Int {
        var cursor = offset
        val end = offset + length
        var count = 0

        while (cursor + 4 <= end) {
            val optionLength = readU16(packet, cursor + 2)
            cursor += 4 + optionLength
            if (cursor > end) break
            count++
        }

        return count
    }

    private class ParsedName(val text: String, val nextOffset: Int)

    private fun readName(packet: ByteArray, startOffset: Int): ParsedName? {
        val labels = StringBuilder()
        var offset = startOffset
        var nextOffset = -1
        var hops = 0
        var nameLength = 0

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
            if (length > MAX_LABEL_LENGTH) return null
            if (offset + 1 + length > packet.size) return null

            nameLength += length + 1
            if (nameLength > MAX_NAME_LENGTH) return null

            if (labels.isNotEmpty()) labels.append('.')
            labels.append(decodeLabel(packet, offset + 1, length))
            offset += 1 + length
        }

        return ParsedName(labels.toString(), nextOffset)
    }

    private fun decodeLabel(packet: ByteArray, offset: Int, length: Int): String =
        String(packet, offset, length, StandardCharsets.ISO_8859_1)

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)

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
