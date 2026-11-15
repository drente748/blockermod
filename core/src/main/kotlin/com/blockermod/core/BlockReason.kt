package com.blockermod.core

/**
 * Why a domain was blocked.
 */
enum class BlockReason {
    /** Matched the adult content blocklist. */
    BLOCKLIST_ADULT,

    /** Matched the bypass attempt blocklist. */
    BLOCKLIST_BYPASS,

    /** Matched the blocklist of engines the engine cannot support. */
    BLOCKLIST_UNSUPPORTED_ENGINE,

    /** Matched the canary domain used to detect apps that bypass the DNS filter. */
    CANARY,

    /** The user is currently locked out. */
    USER_PAUSED,

    /** The device is in recovery mode. */
    RECOVERY_MODE,
}
