/*
 * Copyright (C) 2026 Curity AB. All rights reserved.
 *
 * The contents of this file are the property of Curity AB.
 * You may not copy or use this file, in either source code
 * or executable form, except in compliance with terms
 * set by Curity AB.
 *
 * For further information, please contact Curity AB.
 */

package io.curity.identityserver.plugin.credentials.hardenedhashing.argon2

/**
 * The bounds applied to Argon2 parameters. The constants play two distinct roles:
 *
 * The minimums (except [MIN_MEMORY_COST_PER_LANE] and [MIN_STORED_HASH_LENGTH]) apply to the plugin
 * *configuration*. They are floors below every configuration that RFC 9106 or the OWASP Password Storage
 * Cheat Sheet recommends, so no recommended parameter set is rejected, while values that appear in no
 * recommendation at all cannot be used to hash new passwords. Combinations are deliberately not validated
 * against each other: trading memory against passes is exactly the tuning RFC 9106 (section 4) describes, and
 * per-setting bounds cannot judge a combination. The defaults and the setting descriptions steer towards the
 * recommended combinations.
 *
 * The maximums apply both to the configuration and to parameters read back out of a *stored* password.
 * Verifying a password uses the parameters encoded in the stored value, not the configured ones, so that a
 * password hashed with older settings (or by another Argon2 implementation) can still be verified. Those
 * parameters are therefore untrusted input: a stored value asking for a memory cost of several gibibytes, or
 * for thousands of passes over it, would make a single verification exhaust the heap or occupy a hashing
 * permit for hours. On the minimum side, stored values are held only to what the algorithm itself defines
 * ([MIN_MEMORY_COST_PER_LANE], [MIN_STORED_HASH_LENGTH], and [MIN_ITERATIONS] and [MIN_PARALLELISM], which
 * are 1 for the algorithm as much as for the configuration), so that weaker hashes produced elsewhere remain
 * verifiable — and thereby upgradeable on login.
 *
 * Every bound on a stored value is applied in one place, [Argon2PhcFormat.decode], so that nothing this
 * plugin will not compute reaches the hashing function.
 */
internal object Argon2Limits {

    /**
     * Argon2 does not define a hash for a memory cost below 8 kibibytes per lane (RFC 9106, section 3.1:
     * m >= 8p). Stored values are held to this floor rather than to [MIN_MEMORY_COST], so that hashes
     * produced by implementations configured with less memory than this plugin allows can still be verified.
     */
    const val MIN_MEMORY_COST_PER_LANE = 8

    /**
     * The lowest memory cost, in kibibytes, that may be configured (7 MiB).
     *
     * A security floor rather than a limit of the algorithm: 7168 is the memory cost of the most
     * memory-frugal Argon2id configuration OWASP recommends (m=7168, t=5), so every recommended
     * configuration remains admissible while anything below all of them is rejected. RFC 9106's own
     * recommended options use far more (64 MiB and 2 GiB).
     *
     * It is also deliberately kept above [MIN_MEMORY_COST_PER_LANE] * [MAX_PARALLELISM] (2040), which means
     * any configured memory cost is valid for any configured parallelism and no cross-setting validation is
     * needed for the resulting hash to be one other Argon2 implementations accept.
     */
    const val MIN_MEMORY_COST = 7168.0

    /**
     * The highest memory cost, in kibibytes, that may be configured or accepted from a stored password (1 GiB).
     *
     * The memory is allocated on the Java heap for the duration of each hashing operation, and a server node
     * is recommended to run with 8 GiB of total RAM, of which the heap is only a part. RFC 9106's first
     * recommended option (2 GiB) is deliberately out of range: it is meant for deployments where 2 GiB per
     * call is affordable, and on a recommended node even a single such computation would compete with
     * everything else on the heap. The uniformly safe choice here is the RFC's second recommended option
     * (64 MiB, this plugin's default). Even 1 GiB is only usable with `max-concurrent-operations` reduced to
     * a small number, since the heap must hold `memory-cost * max-concurrent-operations` at peak.
     */
    const val MAX_MEMORY_COST = (1024 * 1024).toDouble()

    /**
     * A single pass is the algorithm's minimum and is a recommended setting when paired with a high memory
     * cost: RFC 9106's first recommended option uses t=1 (with 2 GiB), and OWASP lists m=47104, t=1 as
     * equivalent to its other Argon2id options. Rejecting t=1 would forbid configurations stronger than
     * recommended ones. Note that Argon2i (unlike Argon2id) has known attacks against fewer than 3 passes;
     * the default (3) is safe for every Argon2 type.
     */
    const val MIN_ITERATIONS = 1.0

    /**
     * No recommended configuration uses more than 5 passes (OWASP's most memory-frugal option, t=5 at 7 MiB):
     * making hashes more expensive is done by raising the memory cost, which is what makes Argon2 hard to
     * attack, not by adding passes. A pass count in the hundreds is therefore either a misconfiguration or a
     * hostile stored value trying to occupy a verification thread for hours. Verification time grows with
     * `memory-cost * iterations`, so this cap together with [MAX_MEMORY_COST] bounds how long a single stored
     * value can keep a hashing permit busy, while still being over an order of magnitude above any
     * legitimate value.
     */
    const val MAX_ITERATIONS = 128.0

    const val MIN_PARALLELISM = 1.0

    /**
     * RFC 9106 recommends p=4, and although the algorithm accepts up to 2^24-1 lanes, lanes beyond the
     * machine's core count serve no purpose — and this server computes every hash in a single thread
     * regardless, so the parallelism only affects the shape of the resulting hash. 255 is far above anything
     * a legitimate implementation produces, keeps 8 * [MAX_PARALLELISM] below [MIN_MEMORY_COST] (see there),
     * and keeps the per-lane memory check on stored values free of integer overflow.
     */
    const val MAX_PARALLELISM = 255.0

    /**
     * RFC 9106 recommends a 128-bit salt but explicitly allows reducing it to 64 bits where space is
     * constrained, and the argon2 reference implementation accepts nothing shorter than 8 bytes, so no
     * legitimate hash has a shorter salt.
     */
    const val MIN_SALT_LENGTH = 8.0

    /**
     * A salt longer than 16 bytes adds nothing (RFC 9106: 128 bits is sufficient for all applications), so
     * this only needs to be generous enough to accept anything a legitimate implementation might have
     * produced. Its purpose is to bound the size of the untrusted stored values that get decoded and fed to
     * the hash function.
     */
    const val MAX_SALT_LENGTH = 1024.0

    /**
     * The shortest tag Argon2 defines is 4 bytes. Stored values are held to this floor rather than to
     * [MIN_HASH_LENGTH], so that hashes produced elsewhere with shorter tags can still be verified.
     */
    const val MIN_STORED_HASH_LENGTH = 4.0

    /**
     * The shortest tag that may be configured. RFC 9106 recommends 128 bits as sufficient for most
     * applications and no recommendation goes lower for password storage, so tags shorter than 16 bytes are
     * only accepted when verifying a stored value (see [MIN_STORED_HASH_LENGTH]), never produced.
     */
    const val MIN_HASH_LENGTH = 16.0

    /**
     * Like [MAX_SALT_LENGTH], a bound on the size of untrusted stored values rather than a limit of the
     * algorithm: both RFC 9106 recommended options use a 32-byte tag and no implementation defaults to more
     * than 64 bytes, so 1024 accepts anything legitimate.
     */
    const val MAX_HASH_LENGTH = 1024.0

    /**
     * With no permit, no hash could ever be computed.
     */
    const val MIN_CONCURRENT_OPERATIONS = 1.0

    /**
     * Each hashing operation is CPU-bound and runs in a single thread, so permits beyond the machine's core
     * count add waiting time but no throughput; 256 comfortably covers any realistic core count. Keeping the
     * cap low also keeps the peak-heap bound `memory-cost * max-concurrent-operations` meaningful: even at
     * the default memory cost of 64 MiB, 256 concurrent operations would need 16 GiB of heap — more than a
     * recommended 8 GiB node has in total.
     */
    const val MAX_CONCURRENT_OPERATIONS = 256.0
}
