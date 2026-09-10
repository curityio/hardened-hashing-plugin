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

import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_BLOCK_SIZE
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_CONCURRENT_OPERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_COST_EXPONENT
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_PARALLELIZATION
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_SALT_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_BLOCK_SIZE
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_CONCURRENT_OPERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_COST_EXPONENT
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_PARALLELIZATION
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_SALT_LENGTH
import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.annotation.DefaultInteger
import se.curity.identityserver.sdk.config.annotation.Description
import se.curity.identityserver.sdk.config.annotation.RangeConstraint

/**
 * The configuration of the scrypt algorithm.
 *
 * The defaults follow the first configuration recommended by the OWASP Password Storage Cheat Sheet
 * (N = 2^17, r = 8, p = 1), which uses 128 MiB of memory per hash.
 */
interface ScryptConfiguration : Configuration {

    @get:DefaultInteger(17)
    @get:RangeConstraint(min = MIN_COST_EXPONENT, max = MAX_COST_EXPONENT)
    @get:Description(
        "The base-2 logarithm of scrypt's CPU/memory cost parameter N: the hash uses N = 2^cost-exponent " +
                "blocks of memory. Increasing it by one doubles both the memory and the time a hash takes. " +
                "The memory, 128 * 'block-size' * 2^cost-exponent bytes, is allocated on the Java heap for " +
                "the duration of every credential verification: the heap must have room for this much " +
                "memory multiplied by 'max-concurrent-operations'. The default of 17 (128 MiB with the " +
                "default block size) is the value recommended by OWASP."
    )
    val costExponent: Int

    @get:DefaultInteger(8)
    @get:RangeConstraint(min = MIN_BLOCK_SIZE, max = MAX_BLOCK_SIZE)
    @get:Description(
        "scrypt's block size parameter r. Every published recommendation uses the default of 8; make " +
                "hashes more expensive by raising 'cost-exponent', not this."
    )
    val blockSize: Int

    @get:DefaultInteger(1)
    @get:RangeConstraint(min = MIN_PARALLELIZATION, max = MAX_PARALLELIZATION)
    @get:Description(
        "scrypt's parallelization parameter p. Note that the server always computes the hash in a single " +
                "thread, so raising this multiplies how long a hash takes without increasing the memory it " +
                "uses."
    )
    val parallelization: Int

    @get:DefaultInteger(16)
    @get:RangeConstraint(min = MIN_SALT_LENGTH, max = MAX_SALT_LENGTH)
    @get:Description("The size, in bytes, of the randomly generated salt.")
    val saltLength: Int

    @get:DefaultInteger(32)
    @get:RangeConstraint(min = MIN_HASH_LENGTH, max = MAX_HASH_LENGTH)
    @get:Description("The size, in bytes, of the computed hash.")
    val hashLength: Int

    @get:DefaultInteger(4)
    @get:RangeConstraint(min = MIN_CONCURRENT_OPERATIONS, max = MAX_CONCURRENT_OPERATIONS)
    @get:Description(
        "How many scrypt hashes this password transformer may compute at the same time. Each computation " +
                "holds the per-hash memory while it runs — 128 * 'block-size' * 2^cost-exponent bytes " +
                "when hashing a new password, up to 1 GiB when verifying a hash stored with heavier " +
                "parameters — so this setting is what bounds the memory scrypt can use. Requests over the " +
                "limit wait for their turn rather than being rejected. Raising it increases authentication " +
                "throughput and the memory needed; every password transformer has its own limit, shared by " +
                "the credential managers using it."
    )
    val maxConcurrentOperations: Int
}
