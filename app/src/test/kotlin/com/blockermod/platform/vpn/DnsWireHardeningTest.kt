package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import kotlin.test.Test
import kotlin.test.assertTrue

/** The 16-bit answer count must never size an allocation from a short packet (B8). */
class DnsWireHardeningTest {

    @Test
    fun `a response with more answers than the cap is rejected`() {
        val query = DnsCodec.parseQuery(DnsWire.buildQuery(1, "many.example", DnsTypes.A))!!
        val records = (1..(DnsWire.MAX_ANSWERS + 1)).map { index ->
            DnsRecord("many.example", DnsTypes.A, 1, 60, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), index.toByte()))
        }

        val response = DnsCodec.buildAnswer(query, records)

        assertTrue(DnsWire.parseAnswers(response).isEmpty())
    }
}
