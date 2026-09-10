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

import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult
import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult.Decoded
import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult.Invalid
import io.curity.identityserver.plugin.credentials.hardenedhashing.getOrElse
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_HASH_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_ITERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_MEMORY_COST
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_PARALLELISM
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MAX_SALT_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_ITERATIONS
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_MEMORY_COST_PER_LANE
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_PARALLELISM
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_SALT_LENGTH
import io.curity.identityserver.plugin.credentials.hardenedhashing.argon2.Argon2Limits.MIN_STORED_HASH_LENGTH
import java.util.Base64

/**
 * An Argon2 hash together with the parameters used to compute it.
 */
data class Argon2Hash(val parameters: Argon2InputParameters, val hash: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Argon2Hash) return false

        return parameters == other.parameters && hash.contentEquals(other.hash)
    }

    override fun hashCode() = 31 * parameters.hashCode() + hash.contentHashCode()

    override fun toString() = "Argon2Hash(parameters=$parameters, hashLength=${hash.size})"
}

/**
 * Encodes and decodes Argon2 hashes using the
 * [PHC string format](https://c2sp.org/phc-strings), which is what
 * the Argon2 reference implementation and most other implementations use:
 *
 * ```
 * $argon2id$v=19$m=65536,t=3,p=1$<base64 salt>$<base64 hash>
 * ```
 *
 * As mandated by the specification, the base64 encoding is the standard one but without padding.
 */
object Argon2PhcFormat {

    private val encoder: Base64.Encoder = Base64.getEncoder().withoutPadding()
    private val decoder: Base64.Decoder = Base64.getDecoder()

    private object Params {
        const val VERSION = "v"
        const val MEMORY = "m"
        const val ITERATIONS = "t"
        const val PARALLELISM = "p"
    }

    fun encode(hash: Argon2Hash): String = with(hash.parameters) {
        with(Params) {
            $$"$$${type.algorithmName}" +
                    $$"$$$VERSION=$$version" +
                    $$"$$$MEMORY=$$memoryCostInKibibytes,$$ITERATIONS=$$iterations,$$PARALLELISM=$$parallelism" +
                    $$"$$${encoder.encodeToString(salt)}" +
                    $$"$$${encoder.encodeToString(hash.hash)}"
        }
    }

    /**
     * Decodes an encoded Argon2 hash.
     *
     * Encoded hashes come out of the credential store, so they are untrusted input: anything that is not a
     * hash this transformer could verify is rejected here rather than being passed on to the hashing function,
     * which would either compute a result nobody else agrees with, throw, or allocate without bound. See
     * [Argon2Limits].
     *
     * @return the decoded hash, or an [Invalid] carrying a short reason why the given value is not one this
     * transformer can verify. The reason is meant for the server's log, see [PhcDecodeResult].
     */
    fun decode(encoded: String): PhcDecodeResult<Argon2Hash> {
        val expectedSegments = 6

        // the leading '$' makes the first segment empty
        val segments = encoded.split('$', limit = expectedSegments + 1)

        if (segments.size != expectedSegments || segments[0].isNotEmpty()) {
            return Invalid("not a PHC string with the $expectedSegments fields an Argon2 hash has")
        }

        // the name is not repeated: it comes from an untrusted stored value
        val type = Argon2Type.fromAlgorithmName(segments[1])
            ?: return Invalid("the algorithm is not one of the Argon2 variants")
        val version = segments[2].removePrefixOrNull("${Params.VERSION}=")?.toIntOrNull()
            ?: return Invalid("the '${Params.VERSION}' field is missing or not a number")
        val (memoryCost, iterations, parallelism) = parseCostParameters(segments[3])
            .getOrElse { return Invalid(it) }
        val salt = decodeBase64(segments[4]) ?: return Invalid("the salt is not valid base64")
        val hash = decodeBase64(segments[5]) ?: return Invalid("the hash is not valid base64")

        if (salt.size !in MIN_SALT_LENGTH.toInt()..MAX_SALT_LENGTH.toInt()) {
            return Invalid(
                "the salt length ${salt.size} is outside the accepted " +
                        "${MIN_SALT_LENGTH.toInt()}..${MAX_SALT_LENGTH.toInt()}"
            )
        }

        if (hash.size !in MIN_STORED_HASH_LENGTH.toInt()..MAX_HASH_LENGTH.toInt()) {
            return Invalid(
                "the hash length ${hash.size} is outside the accepted " +
                        "${MIN_STORED_HASH_LENGTH.toInt()}..${MAX_HASH_LENGTH.toInt()}"
            )
        }

        return Decoded(
            Argon2Hash(
                Argon2InputParameters(type, version, memoryCost, iterations, parallelism, salt),
                hash
            )
        )
    }

    private fun parseCostParameters(segment: String): PhcDecodeResult<Triple<Int, Int, Int>> {
        // null means the parameter has not been seen yet, which no in-range value can stand in for
        var memoryCostOrNull: Int? = null
        var iterationsOrNull: Int? = null
        var parallelismOrNull: Int? = null

        fun getIfUnsetAndValid(previous: Int?, name: String, newValue: String): PhcDecodeResult<Int> = when {
            previous != null -> Invalid("the '$name' parameter appears more than once")
            else -> newValue.toIntOrNull()?.let(::Decoded) ?: Invalid("the '$name' parameter is not a number")
        }

        segment.split(',', limit = 3).asSequence()
            .map { it.split('=', limit = 2) }
            .filter { it.size == 2 }
            .forEach { (name, value) ->
                when (name) {
                    Params.MEMORY ->
                        memoryCostOrNull = getIfUnsetAndValid(memoryCostOrNull, Params.MEMORY, value)
                            .getOrElse { return Invalid(it) }
                    Params.ITERATIONS ->
                        iterationsOrNull = getIfUnsetAndValid(iterationsOrNull, Params.ITERATIONS, value)
                            .getOrElse { return Invalid(it) }
                    Params.PARALLELISM ->
                        parallelismOrNull = getIfUnsetAndValid(parallelismOrNull, Params.PARALLELISM, value)
                            .getOrElse { return Invalid(it) }
                    // the name is not repeated: it comes from an untrusted stored value
                    else -> return Invalid(
                        "an unknown cost parameter is present, expected only '${Params.MEMORY}', " +
                                "'${Params.ITERATIONS}' and '${Params.PARALLELISM}'"
                    )
                }
            }

        val memoryCost = memoryCostOrNull ?: return Invalid("the '${Params.MEMORY}' parameter is missing")
        val iterations = iterationsOrNull ?: return Invalid("the '${Params.ITERATIONS}' parameter is missing")
        val parallelism = parallelismOrNull
            ?: return Invalid("the '${Params.PARALLELISM}' parameter is missing")

        // Computing beyond the maximums would cost more memory or time than this plugin ever asks for, so
        // the value cannot have been produced by any configuration of it. Honouring it would let a single
        // stored credential exhaust the heap or occupy a request thread for an unbounded time. The
        // parallelism is bounded first so that the per-lane memory check below cannot overflow.
        if (parallelism !in MIN_PARALLELISM.toInt()..MAX_PARALLELISM.toInt()) {
            return Invalid(
                "${Params.PARALLELISM}=$parallelism is outside the accepted " +
                        "${MIN_PARALLELISM.toInt()}..${MAX_PARALLELISM.toInt()}"
            )
        }

        if (iterations !in MIN_ITERATIONS.toInt()..MAX_ITERATIONS.toInt()) {
            return Invalid(
                "${Params.ITERATIONS}=$iterations is outside the accepted " +
                        "${MIN_ITERATIONS.toInt()}..${MAX_ITERATIONS.toInt()}"
            )
        }

        if (memoryCost > MAX_MEMORY_COST) {
            return Invalid(
                "${Params.MEMORY}=$memoryCost is more than the ${MAX_MEMORY_COST.toInt()} kibibytes of " +
                        "memory a single hash may use"
            )
        }

        // Argon2 does not define a hash for a memory cost below 8 kibibytes per lane. BouncyCastle silently
        // raises the memory cost instead of failing, which would produce a hash other implementations
        // disagree with, so refuse to verify such data rather than reporting a wrong result.
        if (memoryCost < MIN_MEMORY_COST_PER_LANE * parallelism) {
            return Invalid(
                "${Params.MEMORY}=$memoryCost is below the $MIN_MEMORY_COST_PER_LANE kibibytes per lane " +
                        "Argon2 requires for ${Params.PARALLELISM}=$parallelism"
            )
        }

        return Decoded(Triple(memoryCost, iterations, parallelism))
    }

    private fun decodeBase64(value: String): ByteArray? = try {
        decoder.decode(value)
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun String.removePrefixOrNull(prefix: String): String? =
        if (startsWith(prefix)) substring(prefix.length) else null
}
