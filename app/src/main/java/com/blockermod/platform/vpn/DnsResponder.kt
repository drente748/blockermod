package com.blockermod.platform.vpn

import com.blockermod.core.BlockReason
import com.blockermod.core.BlockingResult
import com.blockermod.core.dns.DnsCodec
import com.blockermod.core.dns.DnsQuery
import com.blockermod.core.dns.DnsRecord
import com.blockermod.core.dns.DnsTypes
import com.blockermod.core.policy.PolicyEngine

/**
 * Turns a DNS query into the answer that must be sent back to the client.
 *
 * The responder is pure: it decides with the [PolicyEngine], asks the upstream resolver for the
 * records it needs, and builds the DNS message. It never touches sockets itself.
 */
internal class DnsResponder(
    private val policy: PolicyEngine,
    private val upstream: DnsUpstream,
    private val logOnly: Boolean = false,
    private val onBlocked: (BlockReason) -> Unit = {},
) {

    /**
     * Records of the decisions taken while the debug mode is on, without any formatting.
     */
    val decisions: DecisionTrail = DecisionTrail()

    /**
     * Answers the given DNS payload.
     *
     * Returns null when the payload is not a query and must be dropped.
     */
    fun respond(payload: ByteArray): ByteArray? {
        val query = DnsCodec.parseQuery(payload) ?: return null
        val decision = policy.evaluate(query.question.name)

        if (logOnly) {
            decisions.record(decision)
            return forward(query)
        }

        return when (decision) {
            is BlockingResult.Allowed -> forward(query)
            is BlockingResult.Blocked -> {
                onBlocked(decision.reason)
                DnsCodec.buildNxDomain(query)
            }
            is BlockingResult.Rewrite -> rewrite(query, decision.cnameTarget)
            is BlockingResult.Error -> DnsCodec.buildServFail(query)
        }
    }

    private fun forward(query: DnsQuery): ByteArray {
        val records = upstream.lookup(query.question.name, query.question.type)
        if (records.isEmpty()) return DnsCodec.buildServFail(query)
        return DnsCodec.buildAnswer(query, records)
    }

    private fun rewrite(query: DnsQuery, target: String): ByteArray {
        if (query.question.type == DnsTypes.HTTPS || query.question.type == TYPE_SVCB) {
            return DnsCodec.buildNoData(query)
        }

        val records = ArrayList<DnsRecord>()
        records.addAll(upstream.lookup(target, DnsTypes.A))
        records.addAll(upstream.lookup(target, DnsTypes.AAAA))

        if (records.isEmpty()) {
            // Fail closed: the original name is never used as a fallback.
            return DnsCodec.buildServFail(query)
        }

        val ttl = records.minOf { it.ttlSeconds }
        val answers = ArrayList<DnsRecord>(records.size + 1)
        answers.add(DnsRecord(query.question.name, DnsTypes.CNAME, CLASS_IN, ttl, DnsWire.encodeName(target)))
        answers.addAll(records)

        return DnsCodec.buildAnswer(query, answers)
    }

    private companion object {
        /** Record type of the service binding record, handled like HTTPS. */
        const val TYPE_SVCB: Int = 64

        /** The internet class. */
        const val CLASS_IN: Int = 1
    }
}
