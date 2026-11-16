package com.blockermod.platform.vpn

/**
 * Extracts the TLS Server Name Indication (SNI) from the beginning of a TLS ClientHello.
 *
 * This is a best-effort, allocation-light parser for the common case where the whole ClientHello
 * arrives in the first TCP segment. It returns null for anything it cannot parse, so the caller must
 * treat "unknown" as "not a DoH endpoint" and let the connection through.
 */
internal object TlsSniInspector {

    /** True when the bytes look like the start of a TLS ClientHello. */
    fun isClientHello(bytes: ByteArray): Boolean =
        bytes.size >= 5 &&
            (bytes[0].toInt() and 0xFF) == 0x16 && // handshake
            (bytes[1].toInt() and 0xFF) == 0x03 // TLS 3.x

    /**
     * Returns the SNI hostname, or null when absent or malformed.
     */
    fun extract(bytes: ByteArray): String? {
        if (bytes.size < 43) return null
        var p = 5 // skip TLS record header (type, version, length)
        if (u8(bytes, p++) != 0x01) return null // ClientHello
        if (p + 3 > bytes.size) return null
        p += 3 // 3-byte handshake length

        p += 2 // client version
        p += 32 // random
        if (p >= bytes.size) return null
        val sessionIdLength = u8(bytes, p++)
        p += sessionIdLength
        if (p + 2 > bytes.size) return null
        val cipherSuitesLength = u16(bytes, p)
        p += 2 + cipherSuitesLength
        if (p >= bytes.size) return null
        val compressionMethodsLength = u8(bytes, p++)
        p += compressionMethodsLength
        if (p + 2 > bytes.size) return null

        val extensionsLength = u16(bytes, p)
        p += 2
        val extensionsEnd = minOf(p + extensionsLength, bytes.size)

        while (p + 4 <= extensionsEnd) {
            val type = u16(bytes, p)
            val length = u16(bytes, p + 2)
            p += 4
            if (p + length > extensionsEnd) return null
            if (type == 0x0000 && length >= 5) { // server_name extension
                val listLength = u16(bytes, p)
                if (listLength < 5 || listLength + 2 > length) return null
                val nameType = u8(bytes, p + 2)
                if (nameType != 0x00) return null // host_name
                val nameLength = u16(bytes, p + 3)
                val start = p + 5
                if (nameLength == 0 || start + nameLength > p + length) return null
                return String(bytes, start, nameLength, Charsets.US_ASCII)
            }
            p += length
        }
        return null
    }

    private fun u8(bytes: ByteArray, offset: Int): Int = bytes[offset].toInt() and 0xFF

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
}
