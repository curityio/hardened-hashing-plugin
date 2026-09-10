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

import io.curity.identityserver.plugin.credentials.hardenedhashing.HashingLimiter
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_CONCURRENT_OPERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_COST_EXPONENT
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_MEMORY_BYTES
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_PARALLELIZATION
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_SALT_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_STORED_BLOCK_SIZE
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_CONCURRENT_OPERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_PARALLELIZATION
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_BLOCK_SIZE
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_COST_EXPONENT
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_SALT_LENGTH

/**
 * Bounds how many scrypt hashes may be computed at the same time: computing one hash allocates
 * `128 * block-size * 2^cost-exponent` bytes on the Java heap and holds it until the hash is done, so with
 * this limiter in place the memory scrypt can use is at most that amount times `max-concurrent-operations`.
 * See [HashingLimiter] for the full rationale.
 */
class ScryptHashingLimiter(configuration: ScryptConfiguration) :
    HashingLimiter<ScryptConfiguration>(configuration, configuration.maxConcurrentOperations, "scrypt") {

    internal companion object {
        fun hashParameterWithinBounds(blockSize: Int, costExponent: Int): Boolean {
            return 128L * blockSize * (1L shl costExponent) <= MAX_MEMORY_BYTES
        }
    }

    init {
        // Belt and braces: the schema's range constraints keep the configuration inside the (stricter)
        // configurable bounds, but computing a hash must not rest on the schema alone — a configuration
        // arriving another way could otherwise overflow `1 shl cost-exponent` in the transformer or
        // allocate without bound. Validated once here, because this managed object is created exactly once
        // per configuration, and against the generous stored-value bounds of ScryptPhcFormat.decode rather
        // than the configurable ones, so it only rejects what no stored value may ask for either.
        with(configuration) {
            require(costExponent in MIN_STORED_COST_EXPONENT..MAX_COST_EXPONENT.toInt()) {
                "cost-exponent must be in $MIN_STORED_COST_EXPONENT..${MAX_COST_EXPONENT.toInt()}, was $costExponent"
            }
            require(blockSize in MIN_STORED_BLOCK_SIZE..MAX_STORED_BLOCK_SIZE) {
                "block-size must be in $MIN_STORED_BLOCK_SIZE..$MAX_STORED_BLOCK_SIZE, was $blockSize"
            }
            require(!(blockSize == 1 && costExponent >= 16)) {
                "scrypt does not define a hash for block-size 1 with cost-exponent 16 or above"
            }
            require(hashParameterWithinBounds(blockSize, costExponent)) {
                "cost-exponent $costExponent with block-size $blockSize needs more than the " +
                        "$MAX_MEMORY_BYTES bytes of memory a hash may use"
            }
            require(parallelization in MIN_PARALLELIZATION.toInt()..MAX_PARALLELIZATION.toInt()) {
                "parallelization must be in ${MIN_PARALLELIZATION.toInt()}..${MAX_PARALLELIZATION.toInt()}, " +
                        "was $parallelization"
            }
            require(saltLength in MIN_STORED_SALT_LENGTH..MAX_SALT_LENGTH.toInt()) {
                "salt-length must be in $MIN_STORED_SALT_LENGTH..${MAX_SALT_LENGTH.toInt()}, was $saltLength"
            }
            require(hashLength in MIN_STORED_HASH_LENGTH.toInt()..MAX_HASH_LENGTH.toInt()) {
                "hash-length must be in ${MIN_STORED_HASH_LENGTH.toInt()}..${MAX_HASH_LENGTH.toInt()}, " +
                        "was $hashLength"
            }
            require(maxConcurrentOperations in MIN_CONCURRENT_OPERATIONS.toInt()..MAX_CONCURRENT_OPERATIONS.toInt()) {
                "max-concurrent-operations must be in ${MIN_CONCURRENT_OPERATIONS.toInt()}..${MAX_CONCURRENT_OPERATIONS.toInt()}, " +
                        "was $maxConcurrentOperations"
            }
        }
    }
}
