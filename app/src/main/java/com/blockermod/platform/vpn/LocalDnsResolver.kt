package com.blockermod.platform.vpn

import com.blockermod.core.BlockReason
import com.blockermod.core.BlockingResult
import com.blockermod.core.DomainMatcher
import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsQuery
import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
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

    private fun resolveQuery(query: DnsQuery, udpPayloadSize: Int?): ByteArray = when (val decision = if (bypassPolicy) BlockingResult.Allowed else policy.evaluate(query.question.name)) {
        is BlockingResult.Blocked -> {
            onBlocked(decision.reason)
            DnsCodec.buildNxDomain(query)
        }
        is BlockingResult.Rewrite -> rewrite(query, decision.cnameTarget, udpPayloadSize)
        is BlockingResult.Error -> DnsCodec.buildServFail(query)
        is BlockingResult.Allowed -> resolveAllowed(query, udpPayloadSize)
    }

    private fun resolveAllowed(query: DnsQuery, udpPayloadSize: Int?): ByteArray {
        val answer = resolveRecords(query.question.name, query.question.type, depth = 0)
        return when (answer.rcode) {
            DnsWire.RCODE_NXDOMAIN -> DnsCodec.buildNxDomain(query)
            DnsWire.RCODE_NOERROR -> {
                if (answer.records.isEmpty()) DnsCodec.buildNoData(query)
                else if (hasBlockedCname(answer.records)) {
                    onBlocked(BlockReason.BLOCKLIST_ADULT)
                    DnsCodec.buildNxDomain(query)
                } else if (containsPrivateAddress(answer.records) && !isLocalUseName(query.question.name)) {
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

        val answer = upstream.lookup(name, type)
        if (answer.rcode == DnsWire.RCODE_NXDOMAIN) {
            cache.rememberNegative(key, UpstreamResolver.NEGATIVE_TTL_SECONDS)
            return answer
        }
        if (answer.rcode != DnsWire.RCODE_NOERROR || depth >= MAX_CNAME_HOPS) return answer
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

    /** SafeSearch: resolve the canonical target and return CNAME plus A/AAAA records. */
    private fun rewrite(query: DnsQuery, target: String, udpPayloadSize: Int?): ByteArray {
        if (query.question.type == DnsTypes.HTTPS || query.question.type == TYPE_SVCB) {
            return DnsCodec.buildNoData(query)
        }

        val records = ArrayList<DnsRecord>()
        for (type in listOf(DnsTypes.A, DnsTypes.AAAA)) {
            val answer = resolveRecords(target, type, depth = 0)
            if (answer.rcode != DnsWire.RCODE_NOERROR) return DnsCodec.buildServFail(query)
            records.addAll(answer.records)
        }
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
                if (a == 10 || a == 127 || (a == 172 && b in 16..31) ||
                    (a == 192 && b == 168) || (a == 169 && b == 254) || (a == 0 && b == 0)
                ) return true
            }
            if (record.type == DnsTypes.AAAA && record.data.size == 16) {
                val first = record.data[0].toInt() and 0xFF
                val second = record.data[1].toInt() and 0xFF
                if ((first and 0xFE) == 0xFC || (first == 0xFE && (second and 0xC0) == 0x80)) return true
                if (record.data.take(15).all { it == 0.toByte() } && (record.data[15].toInt() and 0xFF) == 1) return true
            }
        }
        return false
    }

    private fun frame(message: ByteArray): ByteArray =
        byteArrayOf((message.size ushr 8).toByte(), message.size.toByte()) + message

    private fun cacheKey(host: String, type: Int): String = "$host/$type"

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
