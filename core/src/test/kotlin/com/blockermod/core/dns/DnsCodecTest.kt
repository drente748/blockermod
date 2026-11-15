package com.blockermod.core.dns

import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsCodecTest {

    @Test
    fun `parses a valid query`() {
        val query = DnsCodec.parseQuery(buildQuery(name = "example.com"))

        assertNotNull(query)
        assertEquals("example.com", query.question.name)
        assertEquals(DnsTypes.A, query.question.type)
        assertEquals(1, query.question.klass)
    }

    @Test
    fun `preserves the query id`() {
        val query = DnsCodec.parseQuery(buildQuery(id = 0xBEEF))

        assertEquals(0xBEEF, query?.id)
    }

    @Test
    fun `rejects a packet shorter than the header`() {
        assertNull(DnsCodec.parseQuery(ByteArray(11)))
    }

    @Test
    fun `rejects a truncated question section`() {
        val packet = buildQuery()
        val truncated = packet.copyOfRange(0, 14)

        assertNull(DnsCodec.parseQuery(truncated))
    }

    @Test
    fun `rejects a reserved label type`() {
        val packet = buildQuery()
        packet[12] = 0x40

        assertNull(DnsCodec.parseQuery(packet))
    }

    @Test
    fun `rejects a name longer than 255 bytes`() {
        val longLabel = "a".repeat(64)
        val name = (0..4).joinToString(".") { longLabel }

        assertNull(DnsCodec.parseQuery(buildQuery(name = name)))
    }

    @Test
    fun `rejects a response packet`() {
        assertNull(DnsCodec.parseQuery(buildQuery(flags = 0x8180)))
    }

    @Test
    fun `rejects a query without question`() {
        val packet = buildQuery()
        packet[4] = 0
        packet[5] = 0

        assertNull(DnsCodec.parseQuery(packet))
    }

    @Test
    fun `rejects a query with two questions`() {
        val packet = buildQuery()
        packet[5] = 2

        assertNull(DnsCodec.parseQuery(packet))
    }

    @Test
    fun `detects the edns opt record`() {
        val query = DnsCodec.parseQuery(buildQuery(withEdns = true))

        assertNotNull(query)
        assertTrue(query.hasEdns)
        assertEquals(1232, query.edns?.payloadSize)
    }

    @Test
    fun `reports no edns when the opt record is absent`() {
        val query = DnsCodec.parseQuery(buildQuery())

        assertNotNull(query)
        assertTrue(!query.hasEdns)
    }

    @Test
    fun `survives a malformed additional section`() {
        val packet = buildQuery(withEdns = true)
        val malformed = packet.copyOfRange(0, 29)

        val query = DnsCodec.parseQuery(malformed)

        assertNotNull(query)
        assertTrue(!query.hasEdns)
    }

    @Test
    fun `rejects a looping compression pointer`() {
        val packet = ByteArray(16)
        writeU16(packet, 0, 0x1234)
        writeU16(packet, 2, 0x0100)
        writeU16(packet, 4, 1)
        packet[12] = 0xC0.toByte()
        packet[13] = 12.toByte()
        writeU16(packet, 14, DnsTypes.A)

        assertNull(DnsCodec.parseQuery(packet))
    }

    @Test
    fun `follows a valid compression pointer`() {
        val packet = ByteArray(43)
        writeU16(packet, 0, 0x4242)
        writeU16(packet, 2, 0x0100)
        writeU16(packet, 4, 1)
        writeU16(packet, 10, 1)
        packet[12] = 0xC0.toByte()
        packet[13] = 30.toByte()
        writeU16(packet, 14, DnsTypes.A)
        writeU16(packet, 16, 1)
        packet[18] = 0xC0.toByte()
        packet[19] = 30.toByte()
        writeU16(packet, 20, DnsTypes.OPT)
        writeU16(packet, 22, 1232)
        writeU32(packet, 24, 0)
        writeU16(packet, 28, 0)
        val name = encodeName("example.com")
        name.copyInto(packet, 30)

        val query = DnsCodec.parseQuery(packet)

        assertNotNull(query)
        assertEquals("example.com", query.question.name)
        assertTrue(query.hasEdns)
        assertEquals(1232, query.edns?.payloadSize)
    }

    @Test
    fun `nx domain response keeps the id and the question`() {
        val query = DnsCodec.parseQuery(buildQuery(id = 0x0102, name = "blocked.test"))!!
        val response = DnsCodec.buildNxDomain(query)

        assertEquals(0x0102, readU16(response, 0))
        assertEquals("blocked.test", readNameText(response, 12))
        assertEquals(1, readU16(response, 4))
    }

    @Test
    fun `nx domain response sets the response code`() {
        val query = DnsCodec.parseQuery(buildQuery())!!
        val response = DnsCodec.buildNxDomain(query)

        assertEquals(3, readU16(response, 2) and 0x0F)
        assertEquals(0x8000, readU16(response, 2) and 0x8000)
    }

    @Test
    fun `no data response is successful and carries no answer`() {
        val query = DnsCodec.parseQuery(buildQuery())!!
        val response = DnsCodec.buildNoData(query)

        assertEquals(0, readU16(response, 2) and 0x0F)
        assertEquals(0, readU16(response, 6))
    }

    @Test
    fun `serv fail response sets the response code`() {
        val query = DnsCodec.parseQuery(buildQuery())!!
        val response = DnsCodec.buildServFail(query)

        assertEquals(2, readU16(response, 2) and 0x0F)
    }

    @Test
    fun `answer response carries the records`() {
        val query = DnsCodec.parseQuery(buildQuery(name = "ads.example.com"))!!
        val record = DnsRecord("ads.example.com", DnsTypes.A, 1, 60, byteArrayOf(10, 0, 0, 1))
        val response = DnsCodec.buildAnswer(query, listOf(record))
        val answerOffset = 12 + query.questionBytes.size

        assertEquals(1, readU16(response, 6))
        assertEquals(60, readU32(response, answerOffset + 6))
        assertEquals(4, readU16(response, answerOffset + 10))
        assertEquals(10, response[response.size - 4].toInt())
    }

    @Test
    fun `answer response compresses the owner name`() {
        val query = DnsCodec.parseQuery(buildQuery(name = "ads.example.com"))!!
        val record = DnsRecord("ads.example.com", DnsTypes.A, 1, 60, byteArrayOf(10, 0, 0, 1))
        val response = DnsCodec.buildAnswer(query, listOf(record))
        val answerOffset = 12 + query.questionBytes.size

        assertEquals(0xC0, response[answerOffset].toInt() and 0xFF)
        assertEquals(12, response[answerOffset + 1].toInt() and 0xFF)
    }

    @Test
    fun `response flags set the query bit and copy the recursion bit`() {
        val query = DnsCodec.parseQuery(buildQuery(flags = 0x0100))!!
        val response = DnsCodec.buildServFail(query)
        val flags = readU16(response, 2)

        assertEquals(0x8000, flags and 0x8000)
        assertEquals(0x0100, flags and 0x0100)
    }

    @Test
    fun `response echoes the edns opt record`() {
        val query = DnsCodec.parseQuery(buildQuery(withEdns = true))!!
        val response = DnsCodec.buildNxDomain(query)

        assertEquals(1, readU16(response, 10))
        assertEquals(DnsTypes.OPT, readU16(response, response.size - 10))
    }

    @Test
    fun `never throws on random input`() {
        val random = java.util.Random(7)

        repeat(200) {
            val size = random.nextInt(64)
            val packet = ByteArray(size)
            random.nextBytes(packet)

            val query = DnsCodec.parseQuery(packet)
            if (query != null) {
                DnsCodec.buildNxDomain(query)
                DnsCodec.buildNoData(query)
                DnsCodec.buildServFail(query)
            }
        }
    }

    private fun buildQuery(
        id: Int = 0x1234,
        flags: Int = 0x0100,
        name: String = "example.com",
        type: Int = DnsTypes.A,
        klass: Int = 1,
        withEdns: Boolean = false,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, id)
        writeU16(out, flags)
        writeU16(out, 1)
        writeU16(out, 0)
        writeU16(out, 0)
        writeU16(out, if (withEdns) 1 else 0)
        out.write(encodeName(name))
        writeU16(out, type)
        writeU16(out, klass)

        if (withEdns) {
            out.write(0)
            writeU16(out, DnsTypes.OPT)
            writeU16(out, 1232)
            writeU32(out, 0)
            writeU16(out, 0)
        }

        return out.toByteArray()
    }

    private fun encodeName(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (label in name.split('.')) {
            if (label.isEmpty()) continue
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    private fun readNameText(packet: ByteArray, offset: Int): String {
        val labels = mutableListOf<String>()
        var cursor = offset

        while (cursor < packet.size) {
            val length = packet[cursor].toInt() and 0xFF
            if (length == 0) break
            if (length and 0xC0 != 0) break
            labels.add(String(packet, cursor + 1, length, Charsets.ISO_8859_1))
            cursor += 1 + length
        }

        return labels.joinToString(".")
    }

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)

    private fun readU32(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 24) or
            ((packet[offset + 1].toInt() and 0xFF) shl 16) or
            ((packet[offset + 2].toInt() and 0xFF) shl 8) or
            (packet[offset + 3].toInt() and 0xFF)

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 24) and 0xFF).toByte()
        packet[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        packet[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 3] = (value and 0xFF).toByte()
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
