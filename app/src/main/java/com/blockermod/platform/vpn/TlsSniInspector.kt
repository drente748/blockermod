package com.blockermod.platform.vpn

import java.io.ByteArrayOutputStream

/**
 * Result of inspecting an accumulated TLS client stream.
 *
 * [SNI] means a visible server name was parsed. [ECH] means the ClientHello uses Encrypted Client
 * Hello (RFC 9849): the visible name is not the real destination. [UNKNOWN] means no decision can be
 * made from the bytes; [MALFORMED] means the record/handshake lengths are inconsistent.
 */
internal enum class TlsInspection {
    SNI, ECH, UNKNOWN, MALFORMED,
}

internal data class TlsInspectionResult(
    val kind: TlsInspection,
    val serverName: String? = null,
)

/**
 * Stream-based TLS ClientHello inspector.
 *
 * The caller feeds accumulated TCP payload (which may span several segments AND several TLS
 * handshake records). The parser reassembles handshake bytes across records until the full
 * ClientHello is present, validates its structure, and never reads past the bytes it has — it
 * returns UNKNOWN while more bytes are needed. The caller bounds the accumulation buffer
 * (TcpRelay.MAX_TLS_PREFILTER, 64 KiB); the worst case is 128 flows x 64 KiB = 8 MiB (C2).
 */
internal object TlsSniInspector {

    private const val EXT_SERVER_NAME = 0x0000
    private const val EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
    // Legacy ESNI draft extension. 0x000A is supported_groups (present in nearly every modern
    // ClientHello) — treating it as ESNI would misclassify all real traffic as ECH and disable SNI
    // based DoH blocking.
    private const val EXT_ESNI = 0xFFCE

    private val UNKNOWN = TlsInspectionResult(TlsInspection.UNKNOWN)
    private val MALFORMED = TlsInspectionResult(TlsInspection.MALFORMED)

    /** Checks whether the stream starts with a TLS handshake record. */
    fun looksLikeTlsClientStream(bytes: ByteArray): Boolean =
        bytes.size >= 5 &&
            (bytes[0].toInt() and 0xFF) == 0x16 && // handshake record
            (bytes[1].toInt() and 0xFF) == 0x03 // TLS 3.x

    /** Inspects accumulated bytes. Returns SNI/ECH/UNKNOWN/MALFORMED with no exception. */
    fun inspect(bytes: ByteArray): TlsInspectionResult {
        if (bytes.size < 5) return UNKNOWN
        if (!looksLikeTlsClientStream(bytes)) return MALFORMED

        // Reassemble the handshake stream across TLS records (C2).
        val assembled = ByteArrayOutputStream()
        var offset = 0
        while (offset + 5 <= bytes.size) {
            if (u8(bytes, offset) != 0x16) return MALFORMED
            val recordLength = u16(bytes, offset + 3)
            if (recordLength > MAX_RECORD) return MALFORMED
            if (offset + 5 + recordLength > bytes.size) return UNKNOWN // record still arriving
            assembled.write(bytes, offset + 5, recordLength)
            offset += 5 + recordLength
            if (assembled.size() > MAX_HANDSHAKE) return MALFORMED
            if (assembled.size() >= 4) {
                val handshakeLength = u24(assembled.toByteArray(), 1)
                if (handshakeLength > MAX_HANDSHAKE) return MALFORMED
                if (assembled.size() >= 4 + handshakeLength) break // complete ClientHello
            }
        }
        return inspectHandshake(assembled.toByteArray())
    }

    private fun inspectHandshake(bytes: ByteArray): TlsInspectionResult {
        if (bytes.size < 4) return UNKNOWN
        var p = 0
        if (u8(bytes, p++) != 0x01) return MALFORMED // ClientHello
        val handshakeLength = u24(bytes, p)
        p += 3
        if (handshakeLength > MAX_HANDSHAKE) return MALFORMED
        if (bytes.size < 4 + handshakeLength) return UNKNOWN
        val handshakeEnd = 4 + handshakeLength

        if (p + 2 + 32 > handshakeEnd) return UNKNOWN
        p += 2 + 32 // client version + random

        if (p >= handshakeEnd) return UNKNOWN
        val sessionIdLength = u8(bytes, p++)
        p += sessionIdLength
        if (p > handshakeEnd) return UNKNOWN

        if (p + 2 > handshakeEnd) return UNKNOWN
        val cipherSuitesLength = u16(bytes, p)
        p += 2 + cipherSuitesLength
        if (p > handshakeEnd) return UNKNOWN

        if (p >= handshakeEnd) return UNKNOWN
        val compressionLength = u8(bytes, p++)
        p += compressionLength
        if (p > handshakeEnd) return UNKNOWN

        if (p + 2 > handshakeEnd) return UNKNOWN
        val extensionsLength = u16(bytes, p)
        p += 2
        if (extensionsLength > handshakeEnd - p) return UNKNOWN
        val extensionsEnd = p + extensionsLength

        var echSeen = false
        var sni: String? = null
        while (p + 4 <= extensionsEnd) {
            val type = u16(bytes, p)
            val length = u16(bytes, p + 2)
            p += 4
            if (p + length > extensionsEnd) return UNKNOWN
            when (type) {
                EXT_ENCRYPTED_CLIENT_HELLO, EXT_ESNI -> echSeen = true
                EXT_SERVER_NAME -> sni = parseServerName(bytes, p, length)
            }
            p += length
        }
        if (p != extensionsEnd) return MALFORMED
        if (echSeen) return TlsInspectionResult(TlsInspection.ECH, sni)
        return if (sni == null) UNKNOWN else TlsInspectionResult(TlsInspection.SNI, sni)
    }

    private fun parseServerName(bytes: ByteArray, start: Int, length: Int): String? {
        if (length < 5) return null
        val listLength = u16(bytes, start)
        if (listLength + 2 > length) return null
        var p = start + 2
        val end = start + length
        while (p + 3 <= end) {
            val nameType = u8(bytes, p++)
            val nameLength = u16(bytes, p)
            p += 2
            if (p + nameLength > end) return null
            if (nameType == 0x00 && nameLength in 1..MAX_NAME) {
                return String(bytes, p, nameLength, Charsets.US_ASCII)
            }
            p += nameLength
        }
        return null
    }

    private fun u8(bytes: ByteArray, offset: Int): Int = bytes[offset].toInt() and 0xFF

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun u24(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            (bytes[offset + 2].toInt() and 0xFF)

    private const val MAX_RECORD: Int = 16 * 1024
    private const val MAX_HANDSHAKE: Int = 64 * 1024
    private const val MAX_NAME: Int = 253
}
