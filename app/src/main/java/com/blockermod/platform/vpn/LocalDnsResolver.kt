package com.blockermod.platform.vpn

import com.blockermod.core.BlockReason
import com.blockermod.core.BlockingResult
import com.blockermod.core.DomainMatcher
import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsQuery
import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import com.blockermod.core.matcher.DomainNormalizer
import com.blockermod.core.policy.LocalUseNames
import com.blockermod.core.policy.PolicyEngine

/**
 * A complete local DNS resolver: it answers every query itself using the packed policy lists, its
 * own positive/negative cache, and a plain-DNS upstream only for names the policy allows.
 *
 * Everything a resolver needs lives here — policy decision, CNAME chain walking, DNS rebinding
 * protection, SafeSearch rewriting, and answer building — so both UDP and TCP DNS are served from
 * the same code path and no name is ever resolved by the operating system behind our back.
 */
internal class LocalDnsResolver(
    private val policy: PolicyEngine,
    private val upstream: DnsUpstream,
    private val cache: DnsCache,
    private val onBlocked: (BlockReason) -> Unit = {},
    private val bypassPolicy: Boolean = false,
) {

    /** Resolves a raw DNS wire query; null means the payload was not a query and must be dropped.
     *
     * [udpPayloadSize] is the UDP path's client buffer (RFC 6891): answers larger than it are
     * truncated (TC=1) so the client retries over TCP. The TCP path leaves it null.
     */
    fun resolve(payload: ByteArray, udpPayloadSize: Int? = null): ByteArray? {
        val query = DnsCodec.parseQuery(payload) ?: return null
        return resolveQuery(query, udpPayloadSize)
    }

    /** Resolves a DNS-over-TCP message (two-byte length prefix) and returns a framed response. */
    fun resolveFramed(framed: ByteArray): ByteArray? {
        if (framed.size < 2) return null
        val length = ((framed[0].toInt() and 0xFF) shl 8) or (framed[1].toInt() and 0xFF)
        if (length == 0 || framed.size < length + 2) return null
        val response = resolve(framed.copyOfRange(2, 2 + length)) ?: return null
        return frame(response)
    }

    /** The bypass matcher, exposed for TLS SNI based DoH detection in the full-tunnel relay. */
    fun bypassMatcher(): DomainMatcher = policy.bypassMatcher()

    /** Clears the resolver cache; called when the upstream network changes. */
    fun clearCache() = cache.clear()

    private fun resolveQuery(query: DnsQuery, udpPayloadSize: Int?): ByteArray {
        // Normalize ONCE at the boundary: cache keys and policy use the canonical name, while the
        // raw question bytes stay untouched in the response (0x20 clients expect their case back).
        val name = DomainNormalizer.normalize(query.question.name) ?: query.question.name.lowercase()
        return when (val decision = if (bypassPolicy) BlockingResult.Allowed else policy.evaluate(name)) {
            is BlockingResult.Blocked -> {
                onBlocked(decision.reason)
                DnsCodec.buildNxDomain(query)
            }
            is BlockingResult.Rewrite -> rewrite(query, decision.cnameTarget, udpPayloadSize)
            is BlockingResult.Error -> DnsCodec.buildServFail(query)
            is BlockingResult.Allowed -> resolveAllowed(query, name, udpPayloadSize)
        }
    }

    private fun resolveAllowed(query: DnsQuery, name: String, udpPayloadSize: Int?): ByteArray {
        val answer = resolveRecords(name, query.question.type, depth = 0)
        return when (answer.rcode) {
            DnsWire.RCODE_NXDOMAIN -> DnsCodec.buildNxDomain(query)
            DnsWire.RCODE_NOERROR -> {
                if (answer.records.isEmpty()) DnsCodec.buildNoData(query)
                else if (hasBlockedCname(answer.records)) {
                    onBlocked(BlockReason.BLOCKLIST_ADULT)
                    DnsCodec.buildNxDomain(query)
                } else if (containsPrivateAddress(answer.records) && !isLocalUseName(name)) {
                    // DNS rebinding / local-network leak on a public name: fail closed. Local-use
                    // names are allowed to point at private addresses by definition.
                    DnsCodec.buildServFail(query)
                } else {
                    DnsCodec.buildAnswer(query, answer.records, udpPayloadSize)
                }
            }
            else -> DnsCodec.buildServFail(query)
        }
    }

    /**
     * Resolves [name]/[type], following CNAME chains. Returns a flat record set whose RDATA names
     * are already uncompressed by [DnsWire.parseAnswers].
     */
    private fun resolveRecords(name: String, type: Int, depth: Int): DnsWire.Answer {
        val key = cacheKey(name, type)
        cache.getFresh(key)?.let { return DnsWire.Answer(DnsWire.RCODE_NOERROR, it) }
        if (cache.isNegative(key)) return DnsWire.Answer(DnsWire.RCODE_NXDOMAIN, emptyList())

        val upstreamAnswer = upstream.lookup(name, type)
        if (upstreamAnswer.rcode == DnsWire.RCODE_NXDOMAIN) {
            cache.rememberNegative(key, UpstreamResolver.NEGATIVE_TTL_SECONDS)
            return upstreamAnswer
        }
        if (upstreamAnswer.rcode != DnsWire.RCODE_NOERROR) return upstreamAnswer

        // Bailiwick: only records owned by the queried name or one of its subdomains may be cached
        // or returned. An upstream answer carrying names from another zone must never poison the
        // cache or leak into a response for a different query (B8).
        val answer = DnsWire.Answer(
            DnsWire.RCODE_NOERROR,
            upstreamAnswer.records.filter { inBailiwick(it.name, name) },
        )
        if (depth >= MAX_CNAME_HOPS) return answer
        if (answer.records.isEmpty()) {
            // NODATA: cache it as negative so we do not keep asking upstream.
            cache.rememberNegative(key, UpstreamResolver.NEGATIVE_TTL_SECONDS)
            return answer
        }
        cache.put(key, answer.records, answer.records.minOf { it.ttlSeconds })

        val cnames = answer.records.filter { it.type == DnsTypes.CNAME }
        val direct = answer.records.filter { it.type == type }
        if (direct.isNotEmpty() || cnames.isEmpty()) return answer

        val target = DnsWire.readName(cnames.last().data, 0)?.text
        if (target.isNullOrEmpty() || target.equals(name, ignoreCase = true)) return answer

        val next = resolveRecords(target, type, depth + 1)
        if (next.rcode != DnsWire.RCODE_NOERROR) return next
        return DnsWire.Answer(DnsWire.RCODE_NOERROR, answer.records + next.records)
    }

    private fun inBailiwick(owner: String, queried: String): Boolean =
        owner.equals(queried, ignoreCase = true) ||
            owner.endsWith(".$queried", ignoreCase = true)

    /** SafeSearch: resolve the canonical target and return CNAME plus records of the asked type. */
    private fun rewrite(query: DnsQuery, target: String, udpPayloadSize: Int?): ByteArray {
        val qtype = query.question.type
        // HTTPS/SVCB and every other non-address type cannot be synthesized from a SafeSearch
        // target; answering A or AAAA records to such a query would be malformed (B8).
        if (qtype != DnsTypes.A && qtype != DnsTypes.AAAA) return DnsCodec.buildNoData(query)

        val answer = resolveRecords(target, qtype, depth = 0)
        if (answer.rcode != DnsWire.RCODE_NOERROR) return DnsCodec.buildServFail(query)
        val records = answer.records.filter { it.type == qtype }
        if (records.isEmpty()) return DnsCodec.buildServFail(query)

        val ttl = records.minOf { it.ttlSeconds }
        val answers = ArrayList<DnsRecord>(records.size + 1)
        answers.add(DnsRecord(query.question.name, DnsTypes.CNAME, CLASS_IN, ttl, DnsWire.encodeName(target)))
        answers.addAll(records)
        return DnsCodec.buildAnswer(query, answers, udpPayloadSize)
    }

    private fun hasBlockedCname(records: List<DnsRecord>): Boolean {
        for (record in records) {
            if (record.type != DnsTypes.CNAME) continue
            val target = DnsWire.readName(record.data, 0)?.text ?: continue
            if (target.isNotEmpty() && policy.evaluate(target) is BlockingResult.Blocked) return true
        }
        return false
    }

    /** True when an answer points at a private address, which is a DNS rebinding indicator. */
    private fun containsPrivateAddress(records: List<DnsRecord>): Boolean {
        for (record in records) {
            if (record.type == DnsTypes.A && record.data.size == 4) {
                val a = record.data[0].toInt() and 0xFF
                val b = record.data[1].toInt() and 0xFF
                val c = record.data[2].toInt() and 0xFF
                if (a == 0 || a == 10 || a == 127 || // unspecified, private, loopback
                    (a == 172 && b in 16..31) || (a == 192 && b == 168) ||
                    (a == 169 && b == 254) || // link local
                    (a == 100 && b in 64..127) || // CGNAT (RFC 6598)
                    (a == 192 && b == 0 && c == 0) || // IETF protocol assignments
                    (a == 198 && (b == 18 || b == 19)) || // benchmarking (RFC 2544)
                    (a == 192 && b == 0 && c == 2) ||
                    (a == 198 && b == 51 && c == 100) ||
                    (a == 203 && b == 0 && c == 113) || // documentation networks
                    a >= 224 // multicast + reserved
                ) return true
            }
            if (record.type == DnsTypes.AAAA && record.data.size == 16) {
                val first = record.data[0].toInt() and 0xFF
                val second = record.data[1].toInt() and 0xFF
                if ((first and 0xFE) == 0xFC || (first == 0xFE && (second and 0xC0) == 0x80)) return true
                if (record.data.take(15).all { it == 0.toByte() } &&
                    (record.data[15].toInt() and 0xFF).let { it == 0 || it == 1 }
                ) return true // unspecified :: and loopback ::1
                if (first == 0xFF) return true // multicast
                if (first == 0x20 && second == 0x01 && (record.data[2].toInt() and 0xFF) == 0x0D &&
                    (record.data[3].toInt() and 0xFF) == 0xB8
                ) return true // documentation 2001:db8::/32
                // IPv4-mapped ::ffff:a.b.c.d: apply the IPv4 rules to the embedded address.
                if (record.data.take(10).all { it == 0.toByte() } &&
                    (record.data[10].toInt() and 0xFF) == 0xFF &&
                    (record.data[11].toInt() and 0xFF) == 0xFF
                ) {
                    val mapped = record.data.copyOfRange(12, 16)
                    if (containsPrivateAddress(listOf(DnsRecord("", DnsTypes.A, 1, 0, mapped)))) return true
                }
            }
        }
        return false
    }

    private fun frame(message: ByteArray): ByteArray =
        byteArrayOf((message.size ushr 8).toByte(), message.size.toByte()) + message

    private fun cacheKey(host: String, type: Int): String = "$host/$type"
    // Known limit: the key does not distinguish the DNSSEC DO bit, so a signed and unsigned query
    // for the same name/type share one cache entry. The answer records are identical; only EDNS
    // flags differ and responses are rebuilt from the current query.

    /**
     * True for names reserved for local use, which are expected to resolve to private addresses.
     * Delegates to the shared [com.blockermod.core.policy.LocalUseNames] list (B1).
     */
    private fun isLocalUseName(name: String): Boolean = LocalUseNames.isLocalUseName(name)

    private companion object {
        const val TYPE_SVCB: Int = 64
        const val CLASS_IN: Int = 1
        const val MAX_CNAME_HOPS: Int = 5
    }
}
