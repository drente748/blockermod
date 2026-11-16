package com.blockermod.platform.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class TlsSniInspectorTest {

    @Test
    fun `extracts the server name from a client hello`() {
        val hello = clientHello("cloudflare-dns.com")

        assertEquals("cloudflare-dns.com", TlsSniInspector.extract(hello))
    }

    @Test
    fun `recognizes a client hello`() {
        val hello = clientHello("dns.google")

        assertFalse(!TlsSniInspector.isClientHello(hello))
    }

    @Test
    fun `returns null for a malformed record`() {
        assertNull(TlsSniInspector.extract(byteArrayOf(0x16, 0x03, 0x01, 0, 5)))
    }

    @Test
    fun `returns null when no server name extension exists`() {
        val hello = clientHello("x.example").copyOf()
        // Zero out the extension type (server_name -> unknown) to simulate absence.
        val sniTypeOffset = 5 + 1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 2 + 4
        hello[sniTypeOffset] = 0
        hello[sniTypeOffset + 1] = 0x0A

        assertNull(TlsSniInspector.extract(hello))
    }

    /** Builds a minimal but structurally valid ClientHello with one SNI extension. */
    private fun clientHello(host: String): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val serverName = byteArrayOf(0x00) + u16(hostBytes.size) + hostBytes
        val list = u16(serverName.size) + serverName
        val extension = u16(0x0000) + u16(list.size) + list
        val body =
            u16(0x0303) + // client version
                ByteArray(32) + // random
                byteArrayOf(0x00) + // session id length
                u16(2) + byteArrayOf(0x13, 0x01) + // one cipher suite
                byteArrayOf(0x01, 0x00) + // one compression method
                u16(extension.size) + extension
        val handshake = byteArrayOf(0x01) + u24(body.size) + body
        return byteArrayOf(0x16, 0x03, 0x01) + u16(handshake.size) + handshake
    }

    private fun u16(value: Int): ByteArray =
        byteArrayOf((value ushr 8).toByte(), value.toByte())

    private fun u24(value: Int): ByteArray =
        byteArrayOf((value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())
}
