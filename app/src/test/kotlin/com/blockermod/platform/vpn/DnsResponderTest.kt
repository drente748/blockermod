package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import com.blockermod.core.matcher.InMemoryDomainMatcher
import com.blockermod.core.policy.InMemorySafeSearchTable
import com.blockermod.core.policy.PolicyEngine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsResponderTest {

    @Test
    fun `a blocked domain is answered with a name error`() {
        val responder = responder(adultBlocklist = setOf("adult.example"))

        val response = responder.respond(DnsWire.buildQuery(0x1111, "adult.example", DnsTypes.A))

        assertNotNull(response)
        assertEquals(0x1111, readU16(response, 0))
        assertEquals(3, readU16(response, 2) and 0x0F)
    }

    @Test
    fun `an allowed domain is answered from the upstream`() {
        val upstream = FakeUpstream(
            mapOf("ok.example/1" to listOf(DnsRecord("ok.example", DnsTypes.A, 1, 60, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte())))),
        )
        val responder = responder(upstream = upstream)

        val response = responder.respond(DnsWire.buildQuery(0x2222, "ok.example", DnsTypes.A))

        assertNotNull(response)
        assertEquals(0, readU16(response, 2) and 0x0F)
        assertEquals(1, readU16(response, 6))
    }

    @Test
    fun `a rewrite answers with a canonical name and the target records`() {
        val upstream = FakeUpstream(
            mapOf(
                "forcesafesearch.google.com/1" to
                    listOf(DnsRecord("forcesafesearch.google.com", DnsTypes.A, 1, 60, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte()))),
            ),
        )
        val responder = responder(
            upstream = upstream,
            safeSearchTable = InMemorySafeSearchTable(mapOf("www.google.com" to "forcesafesearch.google.com")),
        )

        val response = responder.respond(DnsWire.buildQuery(0x3333, "www.google.com", DnsTypes.A))

        assertNotNull(response)
        assertEquals(
            listOf(DnsTypes.CNAME, DnsTypes.A),
            answerTypes(response),
            "rcode=${readU16(response, 2) and 0x0F} ancount=${readU16(response, 6)} size=${response.size}",
        )
    }

    @Test
    fun `a rewrite of an https query answers with no data`() {
        val responder = responder(
            safeSearchTable = InMemorySafeSearchTable(mapOf("www.google.com" to "forcesafesearch.google.com")),
        )

        val response = responder.respond(DnsWire.buildQuery(0x4444, "www.google.com", DnsTypes.HTTPS))

        assertNotNull(response)
        assertEquals(0, readU16(response, 2) and 0x0F)
        assertEquals(0, readU16(response, 6))
    }

    @Test
    fun `a rewrite that cannot be resolved answers with a server failure`() {
        val responder = responder(
            safeSearchTable = InMemorySafeSearchTable(mapOf("www.google.com" to "forcesafesearch.google.com")),
        )

        val response = responder.respond(DnsWire.buildQuery(0x5555, "www.google.com", DnsTypes.A))

        assertNotNull(response)
        assertEquals(2, readU16(response, 2) and 0x0F)
    }

    @Test
    fun `a malformed payload is dropped`() {
        assertNull(responder().respond(byteArrayOf(1, 2, 3)))
    }

    @Test
    fun `an upstream name error is forwarded as a name error`() {
        val nxdomain = object : DnsUpstream {
            override fun lookup(host: String, type: Int) =
                DnsWire.Answer(DnsWire.RCODE_NXDOMAIN, emptyList())
        }
        val response = responder(upstream = nxdomain)
            .respond(DnsWire.buildQuery(0x7777, "missing.example", DnsTypes.A))

        assertNotNull(response)
        assertEquals(3, readU16(response, 2) and 0x0F)
    }

    @Test
    fun `a CNAME cloaking an adult domain is blocked`() {
        val cloaking = object : DnsUpstream {
            override fun lookup(host: String, type: Int): DnsWire.Answer {
                val cname = DnsRecord(
                    "clean.example", DnsTypes.CNAME, 1, 60,
                    DnsWire.encodeName("www.pornhub.com"),
                )
                return DnsWire.Answer(DnsWire.RCODE_NOERROR, listOf(cname))
            }
        }
        val response = responder(
            upstream = cloaking,
            adultBlocklist = setOf("www.pornhub.com"),
        ).respond(DnsWire.buildQuery(0x9999, "clean.example", DnsTypes.A))

        assertNotNull(response)
        assertEquals(3, readU16(response, 2) and 0x0F)
    }

    @Test
    fun `an upstream no data answer is forwarded as no data`() {
        val nodata = object : DnsUpstream {
            override fun lookup(host: String, type: Int) =
                DnsWire.Answer(DnsWire.RCODE_NOERROR, emptyList())
        }
        val response = responder(upstream = nodata)
            .respond(DnsWire.buildQuery(0x8888, "existing.example", DnsTypes.AAAA))

        assertNotNull(response)
        assertEquals(0, readU16(response, 2) and 0x0F)
        assertEquals(0, readU16(response, 6))
    }

    @Test
    fun `the log only mode forwards the query and records the decision`() {
        val upstream = FakeUpstream(
            mapOf("adult.example/1" to listOf(DnsRecord("adult.example", DnsTypes.A, 1, 60, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte())))),
        )
        val responder = responder(
            upstream = upstream,
            adultBlocklist = setOf("adult.example"),
            logOnly = true,
        )

        val response = responder.respond(DnsWire.buildQuery(0x6666, "adult.example", DnsTypes.A))

        assertNotNull(response)
        assertEquals(0, readU16(response, 2) and 0x0F)
        assertEquals(1, responder.decisions.size())
        assertTrue(upstream.requestedHosts.contains("adult.example"))
    }

    private fun responder(
        adultBlocklist: Set<String> = emptySet(),
        safeSearchTable: com.blockermod.core.policy.SafeSearchTable = InMemorySafeSearchTable(emptyMap()),
        upstream: DnsUpstream = FakeUpstream(emptyMap()),
        logOnly: Boolean = false,
    ): DnsResponder = DnsResponder(
        policy = PolicyEngine(
            allowlist = InMemoryDomainMatcher(emptySet()),
            adultBlocklist = InMemoryDomainMatcher(adultBlocklist),
            bypassBlocklist = InMemoryDomainMatcher(emptySet()),
            unsupportedEngineBlocklist = InMemoryDomainMatcher(emptySet()),
            safeSearchTable = safeSearchTable,
        ),
        upstream = upstream,
        cache = DnsCache(),
        logOnly = logOnly,
    )

    private class FakeUpstream(private val answers: Map<String, List<DnsRecord>>) : DnsUpstream {

        val requestedHosts: MutableList<String> = mutableListOf()

        override fun lookup(host: String, type: Int): DnsWire.Answer {
            requestedHosts.add(host)
            return DnsWire.Answer(
                DnsWire.RCODE_NOERROR,
                answers["$host/$type"] ?: emptyList(),
            )
        }
    }

    private fun answerOffset(response: ByteArray): Int {
        var offset = 12
        while (offset < response.size) {
            val length = response[offset].toInt() and 0xFF
            if (length == 0) {
                offset++
                break
            }
            if (length and 0xC0 != 0) {
                offset += 2
                break
            }
            offset += 1 + length
        }
        return offset + 4
    }

    private fun answerTypes(response: ByteArray): List<Int> {
        val types = mutableListOf<Int>()
        var offset = answerOffset(response)
        val count = readU16(response, 6)

        repeat(count) {
            while (true) {
                val length = response[offset].toInt() and 0xFF
                if (length == 0) {
                    offset += 1
                    break
                }
                if (length and 0xC0 != 0) {
                    offset += 2
                    break
                }
                offset += 1 + length
            }
            types.add(readU16(response, offset))
            val dataLength = readU16(response, offset + 8)
            offset += 10 + dataLength
        }

        return types
    }

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
}
