package com.blockermod.platform.vpn

import java.net.InetAddress

/**
 * Parses only numeric IP literals — never a hostname.
 *
 * Android's LinkProperties normally carries literals, but a bad value must never make us call
 * [InetAddress.getByName] on a hostname: that would ask the OS to resolve it behind the VPN's
 * back (B9). Pure JVM code so the rule has a unit test.
 */
internal object NumericAddresses {

    fun parse(value: String): InetAddress? {
        val text = value.trim()
        if (!isIpv4Literal(text) && !isIpv6Literal(text)) return null
        return try {
            InetAddress.getByName(text)
        } catch (exception: Exception) {
            null
        }
    }

    private fun isIpv4Literal(text: String): Boolean {
        val parts = text.split('.')
        return parts.size == 4 && parts.all { part ->
            part.isNotEmpty() && part.all { it in '0'..'9' } &&
                part.toIntOrNull()?.inRange(0, 255) == true
        }
    }

    private fun isIpv6Literal(text: String): Boolean =
        text.contains(':') && text.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' ||
            it == ':' || it == '.' || it == '%' }

    private fun Int.inRange(from: Int, to: Int): Boolean = this in from..to
}
