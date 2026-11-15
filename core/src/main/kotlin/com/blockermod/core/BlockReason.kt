package com.blockermod.core

/** Why a domain was blocked (or not). */
enum class BlockReason {
    BLOCKLIST,
    USER_PAUSED,
    RECOVERY_MODE,
}
