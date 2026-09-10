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

package io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt

/**
 * The bounds applied to scrypt parameters. The constants play two distinct
 * roles:
 *
 * The minimums prefixed `MIN_` (except the `MIN_STORED_*` ones) apply to the plugin *configuration*. They are
 * floors below every configuration the OWASP Password Storage Cheat Sheet recommends, so no recommended
 * parameter set is rejected, while values that appear in no recommendation at all cannot be used to hash new
 * passwords. The bounds are chosen so that every combination of configured values is one scrypt defines a
 * hash for, so no cross-leaf validation is needed (see [MIN_BLOCK_SIZE]).
 *
 * The maximums apply both to the configuration and to parameters read back out of a *stored* password.
 * Verifying a password uses the parameters encoded in the stored value, not the configured ones, so that a
 * password hashed with older settings (or by another scrypt implementation) can still be verified. Those
 * parameters are therefore untrusted input: a stored value asking for a huge cost would make a single
 * verification exhaust the heap or occupy a hashing permit for hours. On the minimum side, stored values are
 * held only to what the algorithm itself defines (`MIN_STORED_*`), so that weaker hashes produced elsewhere
 * remain verifiable — and thereby upgradeable on login. The one bound that has to be a combined check is the
 * memory one, [MAX_MEMORY_BYTES], because a stored value's block size may exceed the configurable maximum
 * (see [MAX_STORED_BLOCK_SIZE]) and the memory is the product of the two cost parameters.
 */
internal object ScryptLimits {

    /**
     * The lowest CPU/memory cost exponent (log2 of scrypt's N) that may be configured (N = 2^13 = 8192).
     *
     * A security floor rather than a limit of the algorithm: 2^13 is the cost of the most memory-frugal
     * configuration OWASP recommends (N=2^13, r=8, p=10 — 8 MiB), so every recommended configuration remains
     * admissible while anything below all of them is rejected.
     */
    const val MIN_COST_EXPONENT = 13.0

    /**
     * The highest cost exponent that may be configured or accepted from a stored password (N = 2^20).
     *
     * Together with [MAX_BLOCK_SIZE] this caps the memory a configured hash needs at
     * `128 * 8 * 2^20` bytes = 1 GiB — the same ceiling as the Argon2 plugin's highest memory cost, and like
     * there, only usable with `max-concurrent-operations` reduced to a small number, since the heap must hold
     * `128 * block-size * 2^cost-exponent * max-concurrent-operations` bytes at peak. 2^20 is also the cost
     * scrypt's author suggested for the most sensitive (non-interactive) uses, so nothing recommended is out
     * of reach.
     */
    const val MAX_COST_EXPONENT = 20.0

    /**
     * scrypt requires N > 1, so the smallest exponent a stored value may carry is 1. Stored values are held
     * to this floor rather than to [MIN_COST_EXPONENT], so that hashes produced by implementations configured
     * with a lower cost than this plugin allows can still be verified.
     */
    const val MIN_STORED_COST_EXPONENT = 1

    /**
     * The lowest block size (scrypt's r) that may be configured.
     *
     * The algorithm itself allows r = 1, but with r = 1 scrypt only defines a hash for N below 2^16, and that
     * is the single combination of otherwise-valid settings that would need cross-leaf validation. No
     * recommendation uses a block size below 8 (the value the scrypt paper fixes for its recommendations),
     * so excluding r = 1 from the configuration costs nothing and keeps every configurable combination valid.
     * Stored values with r = 1 are still verified (see [ScryptPhcFormat.decode]).
     */
    const val MIN_BLOCK_SIZE = 2.0

    /**
     * The highest block size that may be configured. Every recommendation uses exactly 8: the memory cost is
     * tuned through the cost exponent, not through the block size. Keeping the configurable maximum at 8 is
     * what makes `128 * block-size * 2^cost-exponent` at most 1 GiB for every configurable combination.
     */
    const val MAX_BLOCK_SIZE = 8.0

    const val MIN_STORED_BLOCK_SIZE = 1

    /**
     * The highest block size accepted from a stored password. Larger than [MAX_BLOCK_SIZE] so that hashes
     * produced elsewhere with an unusual block size remain verifiable; a stored value using it is still
     * subject to the combined [MAX_MEMORY_BYTES] check, which is what actually protects the heap.
     */
    const val MAX_STORED_BLOCK_SIZE = 32

    const val MIN_PARALLELIZATION = 1.0

    /**
     * scrypt's p multiplies CPU time but not peak memory (the p lanes are computed one at a time, reusing
     * the work area). No recommendation goes above p=10 (OWASP's most memory-frugal option); 32 leaves
     * generous headroom for hashes produced elsewhere while bounding how long a single stored value can keep
     * a hashing permit busy.
     */
    const val MAX_PARALLELIZATION = 32.0

    /**
     * The most memory a single hash computation may need, configured or stored: 1 GiB
     * scrypt's work area is `128 * r * N` bytes, allocated on the Java heap for the
     * duration of the computation. Every configurable combination is below this by construction
     * ([MAX_BLOCK_SIZE], [MAX_COST_EXPONENT]); stored values must be checked against it explicitly because
     * their block size may go up to [MAX_STORED_BLOCK_SIZE].
     */
    const val MAX_MEMORY_BYTES = 1024L * 1024 * 1024

    /**
     * The shortest salt that may be configured. RFC 9106-era guidance
     * treat 8 bytes as the floor below which no new hash should be produced.
     */
    const val MIN_SALT_LENGTH = 8.0

    /**
     * scrypt itself defines no salt minimum — RFC 7914's own test vectors use a 4-byte salt — so stored
     * values are held only to being non-empty, keeping weaker hashes produced elsewhere verifiable.
     */
    const val MIN_STORED_SALT_LENGTH = 1

    /**
     * A bound on the size of untrusted stored values rather than a limit of the algorithm.
     */
    const val MAX_SALT_LENGTH = 1024.0

    /**
     * The shortest hash (scrypt's dkLen) that may be configured. 128 bits is the shortest any password
     * storage recommendation produces, so shorter tags are only accepted when verifying a stored value
     * (see [MIN_STORED_HASH_LENGTH]), never produced.
     */
    const val MIN_HASH_LENGTH = 16.0

    /**
     * Stored hashes are held to the same floor as configured ones, unlike every other stored bound in this
     * object. The Argon2 plugin accepts stored hashes as short as 4 bytes, but that leniency cannot be
     * copied: scrypt's final step is PBKDF2-HMAC-SHA256 truncated to the output length, so a short scrypt
     * hash is a *prefix* of the full hash for the same inputs — anyone able to truncate a stored value
     * (without being able to forge one) could turn a strong credential into one that also verifies for any
     * password colliding on the first few bytes. Argon2 is immune because its variable-length hash mixes
     * the output length into the computation, making a truncated hash verify against nothing. No scrypt
     * implementation produces hashes below 16 bytes, so nothing legitimate is lost.
     */
    const val MIN_STORED_HASH_LENGTH = MIN_HASH_LENGTH

    /**
     * Like [MAX_SALT_LENGTH], a bound on the size of untrusted stored values: both RFC 7914 test vectors and
     * common implementations use 32 or 64 bytes, so 1024 accepts anything legitimate.
     */
    const val MAX_HASH_LENGTH = 1024.0

    /**
     * With no permit, no hash could ever be computed.
     */
    const val MIN_CONCURRENT_OPERATIONS = 1.0

    /**
     * Each hashing operation is CPU-bound and runs in a single thread, so permits beyond the machine's core
     * count add waiting time but no throughput; 256 comfortably covers any realistic core count. Keeping the
     * cap low also keeps the peak-heap bound meaningful: even at the default cost (128 MiB per hash), 256
     * concurrent operations would need 32 GiB of heap — far more than a recommended node has in total.
     */
    const val MAX_CONCURRENT_OPERATIONS = 256.0
}
