package com.blockermod.core.dns

/**
 * Extracts the single question section of a DNS message as raw bytes (name + QTYPE + QCLASS).
 *
 * The question section starts at byte 12 (after the fixed header). Compression pointers are illegal
 * in a question, so a pointer or a truncated name is rejected. Returns null when the message has no
 * question (QDCOUNT == 0), which is how the existing in-memory test fixtures are built.
 */
fun extractQuestion(message: ByteArray): ByteArray? {
    if (message.size < 12) return null
    val questionCount = ((message[4].toInt() and 0xFF) shl 8) or (message[5].toInt() and 0xFF)
    if (questionCount != 1) return null

    var offset = 12
    var hops = 0
    while (true) {
        if (offset >= message.size) return null
        val length = message[offset].toInt() and 0xC0
        if (length == 0xC0) return null // compression pointer in a question is illegal
        val labelLength = message[offset].toInt() and 0x3F
        if (labelLength == 0) {
            offset++ // root label terminates the name
            break
        }
        if (offset + 1 + labelLength > message.size) return null
        offset += 1 + labelLength
        if (++hops > 127) return null
    }
    if (offset + 4 > message.size) return null // need QTYPE (2) + QCLASS (2)
    return message.copyOfRange(12, offset + 4)
}

/** Case-insensitive byte comparison of two raw question sections; both null counts as a match. */
fun sameQuestion(a: ByteArray?, b: ByteArray?): Boolean {
    if (a == null || b == null) return a == null && b == null
    if (a.size != b.size) return false
    for (i in a.indices) {
        val x = a[i].toInt() and 0xFF
        val y = b[i].toInt() and 0xFF
        // DNS names are case-insensitive; only ASCII letters need folding.
        val foldedX = if (x in 'A'.code..'Z'.code) x + 32 else x
        val foldedY = if (y in 'A'.code..'Z'.code) y + 32 else y
        if (foldedX != foldedY) return false
    }
    return true
}
