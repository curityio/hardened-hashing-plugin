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

import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_CONCURRENT_OPERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_ITERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_MEMORY_COST
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_PARALLELISM
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_SALT_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_CONCURRENT_OPERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_ITERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_MEMORY_COST
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_PARALLELISM
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_SALT_LENGTH
import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.annotation.DefaultInteger
import se.curity.identityserver.sdk.config.annotation.Description
import se.curity.identityserver.sdk.config.annotation.RangeConstraint

/**
 * The configuration shared by all Argon2 variants.
 *
 * The defaults follow the second recommended configuration of
 * [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4) (64 MiB of memory, 3 iterations),
 * which is also the OWASP recommendation for Argon2id.
 */
interface Argon2Configuration : Configuration {

    // The minimum is a security floor, not a limit of the algorithm, and is comfortably above 8 * the maximum
    // parallelism, which is the lowest memory cost Argon2 allows for any permitted parallelism. Keeping the
    // bounds independent of each other means no cross-leaf validation is needed to guarantee that the
    // resulting hash is one other Argon2 implementations accept. See Argon2Limits.
    @get:DefaultInteger(65536)
    @get:RangeConstraint(min = MIN_MEMORY_COST, max = MAX_MEMORY_COST)
    @get:Description(
        "The amount of memory, in kibibytes, used to compute the hash. Increasing this makes the hash " +
                "harder to compute, but the memory is allocated on the Java heap for the duration of every " +
                "credential verification: the heap must have room for this much memory multiplied by " +
                "'max-concurrent-operations'. The default of 65536 (64 MiB) is the value recommended by " +
                "RFC 9106 and OWASP."
    )
    val memoryCost: Int

    @get:DefaultInteger(3)
    @get:RangeConstraint(min = MIN_ITERATIONS, max = MAX_ITERATIONS)
    @get:Description(
        "The number of passes over memory used to compute the hash, also known as the time cost. A single " +
                "pass is only recommended together with a high memory cost (OWASP recommends at least " +
                "47104 kibibytes in that case), and the argon2i type should always use at least 3 passes. " +
                "The default of 3 is safe for every Argon2 type."
    )
    val iterations: Int

    @get:DefaultInteger(1)
    @get:RangeConstraint(min = MIN_PARALLELISM, max = MAX_PARALLELISM)
    @get:Description(
        "The number of lanes used to compute the hash. Note that the server always computes the hash in a " +
                "single thread, so this only affects the resulting hash, not how fast it is computed."
    )
    val parallelism: Int

    @get:DefaultInteger(16)
    @get:RangeConstraint(min = MIN_SALT_LENGTH, max = MAX_SALT_LENGTH)
    @get:Description("The size, in bytes, of the randomly generated salt.")
    val saltLength: Int

    @get:DefaultInteger(32)
    @get:RangeConstraint(min = MIN_HASH_LENGTH, max = MAX_HASH_LENGTH)
    @get:Description("The size, in bytes, of the computed hash.")
    val hashLength: Int

    @get:DefaultInteger(8)
    @get:RangeConstraint(min = MIN_CONCURRENT_OPERATIONS, max = MAX_CONCURRENT_OPERATIONS)
    @get:Description(
        "How many Argon2 hashes this password transformer may compute at the same time. Each computation " +
                "holds the per-hash memory while it runs — 'memory-cost' kibibytes when hashing a new " +
                "password, up to 1 GiB when verifying a hash stored with heavier parameters — so this " +
                "setting is what bounds the memory Argon2 can use. Requests over the limit wait for their " +
                "turn rather than being rejected. Raising it increases authentication throughput and the " +
                "memory needed; every password transformer has its own limit, shared by the credential " +
                "managers using it."
    )
    val maxConcurrentOperations: Int
}
