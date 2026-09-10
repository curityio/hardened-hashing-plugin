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

import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult
import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult.Decoded
import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult.Invalid
import io.curity.identityserver.plugin.credentials.hardenedhashing.getOrElse
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_COST_EXPONENT
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_MEMORY_BYTES
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_PARALLELIZATION
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_SALT_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MAX_STORED_BLOCK_SIZE
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_PARALLELIZATION
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_BLOCK_SIZE
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_COST_EXPONENT
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.scrypt.ScryptLimits.MIN_STORED_SALT_LENGTH
import java.util.Base64

/**
 * Encodes and decodes scrypt hashes using the
 * [PHC string format](https://c2sp.org/phc-strings), which is what passlib and most other scrypt
 * implementations use:
 *
 * ```
 * $scrypt$ln=17,r=8,p=1$<base64 salt>$<base64 hash>
 * ```
 *
 * `ln` is the base-2 logarithm of the cost parameter N. As mandated by the specification, the base64
 * encoding is the standard one but without padding.
 */
object ScryptPhcFormat {

    const val ALGORITHM_NAME = "scrypt"

    private val encoder: Base64.Encoder = Base64.getEncoder().withoutPadding()
    private val decoder: Base64.Decoder = Base64.getDecoder()

    private object Params {
        const val COST_EXPONENT = "ln"
        const val BLOCK_SIZE = "r"
        const val PARALLELIZATION = "p"
    }

    fun encode(hash: ScryptHash): String = with(hash.parameters) {
        with(Params) {
            $$"$$$ALGORITHM_NAME" +
                    $$"$$$COST_EXPONENT=$$costExponent,$$BLOCK_SIZE=$$blockSize,$$PARALLELIZATION=$$parallelization" +
                    $$"$$${encoder.encodeToString(salt)}" +
                    $$"$$${encoder.encodeToString(hash.hash)}"
        }
    }

    /**
     * Decodes an encoded scrypt hash.
     *
     * Encoded hashes come out of the credential store, so they are untrusted input: anything that is not a
     * hash this transformer could verify is rejected here rather than being passed on to the hashing function,
     * which would either compute a result nobody else agrees with, throw, or allocate without bound. See
     * [ScryptLimits].
     *
     * @return the decoded hash, or an [Invalid] carrying a short reason why the given value is not one this
     * transformer can verify. The reason is meant for the server's log, see [PhcDecodeResult].
     */
    fun decode(encoded: String): PhcDecodeResult<ScryptHash> {
        val expectedSegments = 5

        // the leading '$' makes the first segment empty
        val segments = encoded.split('$', limit = expectedSegments + 1)

        if (segments.size != expectedSegments || segments[0].isNotEmpty()) {
            return Invalid("not a PHC string with the $expectedSegments fields a $ALGORITHM_NAME hash has")
        }

        if (segments[1] != ALGORITHM_NAME) {
            return Invalid("the algorithm is not $ALGORITHM_NAME")
        }

        val (costExponent, blockSize, parallelization) = parseCostParameters(segments[2])
            .getOrElse { return Invalid(it) }
        val salt = decodeBase64(segments[3]) ?: return Invalid("the salt is not valid base64")
        val hash = decodeBase64(segments[4]) ?: return Invalid("the hash is not valid base64")

        if (salt.size !in MIN_STORED_SALT_LENGTH..MAX_SALT_LENGTH.toInt()) {
            return Invalid(
                "the salt length ${salt.size} is outside the accepted " +
                        "$MIN_STORED_SALT_LENGTH..${MAX_SALT_LENGTH.toInt()}"
            )
        }

        if (hash.size !in MIN_STORED_HASH_LENGTH.toInt()..MAX_HASH_LENGTH.toInt()) {
            return Invalid(
                "the hash length ${hash.size} is outside the accepted " +
                        "${MIN_STORED_HASH_LENGTH.toInt()}..${MAX_HASH_LENGTH.toInt()}"
            )
        }

        return Decoded(
            ScryptHash(
                ScryptInputParameters(costExponent, blockSize, parallelization, salt),
                hash
            )
        )
    }

    private fun parseCostParameters(segment: String): PhcDecodeResult<Triple<Int, Int, Int>> {
        // null means the parameter has not been seen yet, which no in-range value can stand in for
        var costExponentOrNull: Int? = null
        var blockSizeOrNull: Int? = null
        var parallelizationOrNull: Int? = null

        fun getIfUnsetAndValid(previous: Int?, name: String, newValue: String): PhcDecodeResult<Int> = when {
            previous != null -> Invalid("the '$name' parameter appears more than once")
            else -> newValue.toIntOrNull()?.let(::Decoded) ?: Invalid("the '$name' parameter is not a number")
        }

        segment.split(',', limit = 3).asSequence()
            .map { it.split('=', limit = 2) }
            .filter { it.size == 2 }
            .forEach { (name, value) ->
                when (name) {
                    Params.COST_EXPONENT ->
                        costExponentOrNull = getIfUnsetAndValid(costExponentOrNull, Params.COST_EXPONENT, value)
                            .getOrElse { return Invalid(it) }

                    Params.BLOCK_SIZE ->
                        blockSizeOrNull = getIfUnsetAndValid(blockSizeOrNull, Params.BLOCK_SIZE, value)
                            .getOrElse { return Invalid(it) }

                    Params.PARALLELIZATION ->
                        parallelizationOrNull =
                            getIfUnsetAndValid(parallelizationOrNull, Params.PARALLELIZATION, value)
                                .getOrElse { return Invalid(it) }

                    // the name is not repeated: it comes from an untrusted stored value
                    else -> return Invalid(
                        "an unknown cost parameter is present, expected only " +
                                "'${Params.COST_EXPONENT}', '${Params.BLOCK_SIZE}' and " +
                                "'${Params.PARALLELIZATION}'"
                    )
                }
            }

        val costExponent = costExponentOrNull
            ?: return Invalid("the '${Params.COST_EXPONENT}' parameter is missing")
        val blockSize = blockSizeOrNull
            ?: return Invalid("the '${Params.BLOCK_SIZE}' parameter is missing")
        val parallelization = parallelizationOrNull
            ?: return Invalid("the '${Params.PARALLELIZATION}' parameter is missing")

        // Computing beyond the maximums would cost more memory or time than this plugin ever asks for, so
        // the value cannot have been produced by any configuration of it. Honouring it would let a single
        // stored credential exhaust the heap or occupy a request thread for an unbounded time.
        if (costExponent !in MIN_STORED_COST_EXPONENT..MAX_COST_EXPONENT.toInt()) {
            return Invalid(
                "${Params.COST_EXPONENT}=$costExponent is outside the accepted " +
                        "$MIN_STORED_COST_EXPONENT..${MAX_COST_EXPONENT.toInt()}"
            )
        }

        if (blockSize !in MIN_STORED_BLOCK_SIZE..MAX_STORED_BLOCK_SIZE) {
            return Invalid(
                "${Params.BLOCK_SIZE}=$blockSize is outside the accepted " +
                        "$MIN_STORED_BLOCK_SIZE..$MAX_STORED_BLOCK_SIZE"
            )
        }

        if (parallelization !in MIN_PARALLELIZATION.toInt()..MAX_PARALLELIZATION.toInt()) {
            return Invalid(
                "${Params.PARALLELIZATION}=$parallelization is outside the accepted " +
                        "${MIN_PARALLELIZATION.toInt()}..${MAX_PARALLELIZATION.toInt()}"
            )
        }

        // scrypt only defines a hash for N below 2^(16 * r); with the exponent capped at 20 the requirement
        // can only bite when r = 1. BouncyCastle throws for such input rather than computing, so refuse to
        // verify it here.
        if (blockSize == 1 && costExponent >= 16) {
            return Invalid(
                "scrypt does not define a hash for ${Params.BLOCK_SIZE}=1 with " +
                        "${Params.COST_EXPONENT}=$costExponent, which needs N below 2^16"
            )
        }

        if (!ScryptHashingLimiter.hashParameterWithinBounds(blockSize, costExponent)) {
            return Invalid(
                "${Params.COST_EXPONENT}=$costExponent with ${Params.BLOCK_SIZE}=$blockSize needs more " +
                        "than the $MAX_MEMORY_BYTES bytes of memory a single hash may use"
            )
        }

        return Decoded(Triple(costExponent, blockSize, parallelization))
    }

    private fun decodeBase64(value: String): ByteArray? = try {
        decoder.decode(value)
    } catch (_: IllegalArgumentException) {
        null
    }
}
