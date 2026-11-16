package com.blockermod.platform.vpn

import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import com.blockermod.core.matcher.InMemoryDomainMatcher
import com.blockermod.core.policy.InMemorySafeSearchTable
import com.blockermod.core.policy.PolicyEngine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class LocalDnsResolverTest {

    @Test
    fun `a blocked domain is answered with NXDOMAIN without touching upstream`() {
        val upstream = CountingUpstream()
        val resolver = resolver(upstream, adult = setOf("porn.example"))

        val response = resolver.resolve(DnsWire.buildQuery(1, "porn.example", DnsTypes.A))

        assertNotNull(response)
        assertEquals(3, rcode(response))
        assertEquals(0, upstream.calls)
    }

    @Test
    fun `an allowed domain is resolved and cached`() {
        val upstream = CountingUpstream { host, type ->
            DnsWire.Answer(
                DnsWire.RCODE_NOERROR,
                listOf(DnsRecord(host, type, 1, 120, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte()))),
            )
        }
        val resolver = resolver(upstream)

        resolver.resolve(DnsWire.buildQuery(2, "ok.example", DnsTypes.A))
        resolver.resolve(DnsWire.buildQuery(3, "ok.example", DnsTypes.A))

        assertEquals(1, upstream.calls, "second lookup must come from the local cache")
    }

    @Test
    fun `NXDOMAIN from upstream is cached`() {
        val upstream = CountingUpstream { _, _ -> DnsWire.Answer(DnsWire.RCODE_NXDOMAIN, emptyList()) }
        val resolver = resolver(upstream)

        resolver.resolve(DnsWire.buildQuery(4, "missing.example", DnsTypes.A))
        resolver.resolve(DnsWire.buildQuery(5, "missing.example", DnsTypes.A))

        assertEquals(1, upstream.calls)
    }

    @Test
    fun `CNAME chain is followed`() {
        val upstream = object : DnsUpstream {
            override fun lookup(host: String, type: Int): DnsWire.Answer = when (host) {
                "alias.example" -> DnsWire.Answer(
                    DnsWire.RCODE_NOERROR,
                    listOf(DnsRecord(host, DnsTypes.CNAME, 1, 60, DnsWire.encodeName("target.example"))),
                )
                else -> DnsWire.Answer(
                    DnsWire.RCODE_NOERROR,
                    listOf(DnsRecord(host, DnsTypes.A, 1, 60, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte()))),
                )
            }
        }
        val resolver = resolver(upstream)

        val response = resolver.resolve(DnsWire.buildQuery(6, "alias.example", DnsTypes.A))

        assertNotNull(response)
        assertEquals(2, answerCount(response))
    }

    @Test
    fun `a private address answer is rejected as rebinding`() {
        val upstream = CountingUpstream { host, type ->
            DnsWire.Answer(
                DnsWire.RCODE_NOERROR,
                listOf(DnsRecord(host, type, 1, 60, byteArrayOf(10.toByte(), 0, 0, 5))),
            )
        }
        val resolver = resolver(upstream)

        val response = resolver.resolve(DnsWire.buildQuery(7, "rebind.example.com", DnsTypes.A))

        assertNotNull(response)
        assertEquals(2, rcode(response))
    }

    @Test
    fun `a local-use name may resolve to a private address`() {
        val upstream = CountingUpstream { host, type ->
            DnsWire.Answer(
                DnsWire.RCODE_NOERROR,
                listOf(DnsRecord(host, type, 1, 60, byteArrayOf(10.toByte(), 0, 0, 5))),
            )
        }
        val resolver = resolver(upstream)

        for (name in listOf("printer.local", "router.home.arpa", "nas", "server.internal")) {
            val response = resolver.resolve(DnsWire.buildQuery(20, name, DnsTypes.A))
            assertNotNull(response, name)
            assertEquals(0, rcode(response), name)
            assertEquals(1, answerCount(response), name)
        }
    }

    @Test
    fun `a public name resolving to a private address is still rejected`() {
        val upstream = CountingUpstream { host, type ->
            DnsWire.Answer(
                DnsWire.RCODE_NOERROR,
                listOf(DnsRecord(host, type, 1, 60, byteArrayOf(10.toByte(), 0, 0, 5))),
            )
        }
        val resolver = resolver(upstream)

        val response = resolver.resolve(DnsWire.buildQuery(21, "public.example.com", DnsTypes.A))

        assertNotNull(response)
        assertEquals(2, rcode(response))
    }

    @Test
    fun `DNS over TCP responses are length framed`() {
        val resolver = resolver(CountingUpstream())

        val framed = resolver.resolveFramed(framedQuery(DnsWire.buildQuery(8, "x.example", DnsTypes.A)))

        assertNotNull(framed)
        val declared = ((framed[0].toInt() and 0xFF) shl 8) or (framed[1].toInt() and 0xFF)
        assertEquals(framed.size - 2, declared)
    }

    @Test
    fun `malformed TCP framing is rejected`() {
        assertNull(resolver(CountingUpstream()).resolveFramed(byteArrayOf(0, 9, 1, 2)))
    }

    private fun resolver(
        upstream: DnsUpstream,
        adult: Set<String> = emptySet(),
    ): LocalDnsResolver = LocalDnsResolver(
        policy = PolicyEngine(
            allowlist = InMemoryDomainMatcher(emptySet()),
            adultBlocklist = InMemoryDomainMatcher(adult),
            bypassBlocklist = InMemoryDomainMatcher(emptySet()),
            unsupportedEngineBlocklist = InMemoryDomainMatcher(emptySet()),
            safeSearchTable = InMemorySafeSearchTable(emptyMap()),
        ),
        upstream = upstream,
        cache = DnsCache(),
    )

    private class CountingUpstream(
        private val answer: (String, Int) -> DnsWire.Answer = { _, _ ->
            DnsWire.Answer(DnsWire.RCODE_NXDOMAIN, emptyList())
        },
    ) : DnsUpstream {
        var calls: Int = 0
            private set

        override fun lookup(host: String, type: Int): DnsWire.Answer {
            calls++
            return answer(host, type)
        }
    }

    private fun framedQuery(query: ByteArray): ByteArray =
        byteArrayOf((query.size ushr 8).toByte(), query.size.toByte()) + query

    private fun rcode(response: ByteArray): Int = response[3].toInt() and 0x0F

    private fun answerCount(response: ByteArray): Int =
        ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
}
