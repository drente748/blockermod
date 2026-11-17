package com.blockermod.core.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsQuestionTest {

    @Test
    fun `extracts the single question section`() {
        val query = minimalQuery("Example.COM", 1)
        val question = extractQuestion(query)

        assertNotNull(question)
        // The question is the encoded name plus QTYPE (2) and QCLASS (2).
        assertTrue(question.size > 4)
        // Case-insensitive matching works on raw bytes.
        assertTrue(sameQuestion(question, extractQuestion(minimalQuery("example.com", 1))))
    }

    @Test
    fun `rejects a message with no question`() {
        assertNull(extractQuestion(ByteArray(12)))
    }

    @Test
    fun `rejects a compression pointer in the question`() {
        val query = minimalQuery("example.com", 1)
        query[12] = 0xC0.toByte()
        query[13] = 0x0C.toByte()

        assertNull(extractQuestion(query))
    }

    @Test
    fun `different questions do not match`() {
        val a = extractQuestion(minimalQuery("a.example", 1))
        val b = extractQuestion(minimalQuery("b.example", 1))
        assertFalse(sameQuestion(a, b))
    }

    @Test
    fun `different qtype does not match`() {
        val a = extractQuestion(minimalQuery("example.com", 1))
        val b = extractQuestion(minimalQuery("example.com", 28))
        assertFalse(sameQuestion(a, b))
    }

    @Test
    fun `both null counts as a match for legacy fixtures`() {
        assertTrue(sameQuestion(null, null))
        assertFalse(sameQuestion(null, ByteArray(4)))
    }

    /** Builds a minimal one-question query (header + QNAME + QTYPE + QCLASS). */
    private fun minimalQuery(name: String, type: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(0); out.write(1) // ID
        out.write(1); out.write(0) // flags: standard query
        out.write(0); out.write(1) // QDCOUNT = 1
        out.write(0); out.write(0) // ANCOUNT
        out.write(0); out.write(0) // NSCOUNT
        out.write(0); out.write(0) // ARCOUNT
        for (label in name.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0) // root
        out.write(0); out.write(type)
        out.write(0); out.write(1) // class IN
        return out.toByteArray()
    }
}
