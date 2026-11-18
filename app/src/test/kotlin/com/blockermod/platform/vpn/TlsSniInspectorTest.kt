package com.blockermod.platform.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TlsSniInspectorTest {

    @Test
    fun `extracts the server name from a client hello`() {
        val result = TlsSniInspector.inspect(clientHello("cloudflare-dns.com"))

        assertEquals(TlsInspection.SNI, result.kind)
        assertEquals("cloudflare-dns.com", result.serverName)
    }

    @Test
    fun `recognizes a tls client stream`() {
        assertTrue(TlsSniInspector.looksLikeTlsClientStream(clientHello("dns.google")))
    }

    @Test
    fun `returns unknown while the client hello is incomplete`() {
        val hello = clientHello("cloudflare-dns.com")

        for (size in 1 until hello.size) {
            val result = TlsSniInspector.inspect(hello.copyOf(size))
            assertFalse(result.kind == TlsInspection.SNI, "prefix $size must not yield a decision")
        }
    }

    @Test
    fun `detects ECH and does not trust the visible name`() {
        val hello = clientHello("public.example.com", ech = true)

        val result = TlsSniInspector.inspect(hello)

        assertEquals(TlsInspection.ECH, result.kind)
        assertEquals("public.example.com", result.serverName)
    }

    @Test
    fun `returns malformed for a broken record`() {
        assertEquals(
            TlsInspection.MALFORMED,
            TlsSniInspector.inspect(byteArrayOf(0x17, 0x03, 0x03, 0, 5, 1)).kind,
        )
    }

    @Test
    fun `returns unknown when no server name extension exists`() {
        val hello = clientHello("x.example").copyOf()
        val sniTypeOffset = 5 + 1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 2 + 4
        hello[sniTypeOffset] = 0
        hello[sniTypeOffset + 1] = 0x0A

        assertEquals(TlsInspection.UNKNOWN, TlsSniInspector.inspect(hello).kind)
    }

    @Test
    fun `a client hello split across two tls records still yields the sni`() {
        val hello = clientHello("cloudflare-dns.com")
        val handshake = hello.copyOfRange(5, hello.size)
        val first = record(handshake.copyOfRange(0, 10))
        val second = record(handshake.copyOfRange(10, handshake.size))

        val result = TlsSniInspector.inspect(first + second)

        assertEquals(TlsInspection.SNI, result.kind)
        assertEquals("cloudflare-dns.com", result.serverName)
    }

    @Test
    fun `a large client hello with the sni at the end is still inspected`() {
        // >16 KiB handshake with a large padding extension before the SNI (post-quantum shape).
        val result = TlsSniInspector.inspect(largeClientHello("dns.google"))

        assertEquals(TlsInspection.SNI, result.kind)
        assertEquals("dns.google", result.serverName)
    }

    @Test
    fun `ech across records is still detected`() {
        val hello = clientHello("public.example.com", ech = true)
        val handshake = hello.copyOfRange(5, hello.size)
        val bytes = record(handshake.copyOfRange(0, 7)) + record(handshake.copyOfRange(7, handshake.size))

        assertEquals(TlsInspection.ECH, TlsSniInspector.inspect(bytes).kind)
    }

    @Test
    fun `random bytes never throw`() {
        val random = java.util.Random(9)
        repeat(500) {
            val bytes = ByteArray(random.nextInt(128))
            random.nextBytes(bytes)
            TlsSniInspector.inspect(bytes) // no exception, any kind is acceptable
        }
    }

    private fun largeClientHello(host: String): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val serverName = byteArrayOf(0x00) + u16(hostBytes.size) + hostBytes
        val sni = u16(0x0000) + u16(serverName.size + 2) + u16(serverName.size) + serverName
        val padding = u16(0x0015) + u16(20_000) + ByteArray(20_000)
        val extensions = padding + sni
        val body = u16(0x0303) + ByteArray(32) + byteArrayOf(0) +
            u16(2) + byteArrayOf(0x13, 0x01) + byteArrayOf(1, 0) +
            u16(extensions.size) + extensions
        val handshake = byteArrayOf(0x01) + u24(body.size) + body
        // Split across several TLS records so no record exceeds 16 KiB.
        val out = java.io.ByteArrayOutputStream()
        var offset = 0
        while (offset < handshake.size) {
            val length = minOf(14_000, handshake.size - offset)
            out.write(byteArrayOf(0x16, 0x03, 0x03))
            out.write(u16(length))
            out.write(handshake, offset, length)
            offset += length
        }
        return out.toByteArray()
    }

    @Test
    fun `supported groups extension does not trigger a false ECH detection`() {
        // 0x000A is supported_groups and appears in virtually every real ClientHello. It must NOT
        // be confused with ESNI, otherwise the visible SNI is discarded and DoH blocking dies.
        val hello = clientHello("dns.google", supportedGroups = true)

        val result = TlsSniInspector.inspect(hello)

        assertEquals(TlsInspection.SNI, result.kind)
        assertEquals("dns.google", result.serverName)
    }

    /** Builds a minimal but structurally valid ClientHello with one SNI extension. */
    private fun clientHello(host: String, ech: Boolean = false, supportedGroups: Boolean = false): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val serverName = byteArrayOf(0x00) + u16(hostBytes.size) + hostBytes
        val sni = u16(0x0000) + u16(serverName.size + 2) + u16(serverName.size) + serverName
        val groups = if (supportedGroups) u16(0x000A) + u16(2) + byteArrayOf(0x00, 0x1D) else EMPTY
        val echExt = if (ech) u16(0xFE0D) + u16(4) + byteArrayOf(1, 2, 3, 4) else EMPTY
        val extensions = sni + groups + echExt
        val body =
            u16(0x0303) + // client version
                ByteArray(32) + // random
                byteArrayOf(0x00) + // session id length
                u16(2) + byteArrayOf(0x13, 0x01) + // cipher suites
                byteArrayOf(0x01, 0x00) + // compression methods
                u16(extensions.size) + extensions
        val handshake = byteArrayOf(0x01) + u24(body.size) + body
        return byteArrayOf(0x16, 0x03, 0x03) + u16(handshake.size) + handshake
    }

    private fun record(payload: ByteArray): ByteArray =
        byteArrayOf(0x16, 0x03, 0x03) + u16(payload.size) + payload

    private fun u16(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())

    private fun u24(value: Int): ByteArray =
        byteArrayOf((value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())

    private companion object {
        val EMPTY = ByteArray(0)
    }
}
