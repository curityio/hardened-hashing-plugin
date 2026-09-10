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

package io.curity.identityserver.plugin.credentials.hardenedhashing

import org.slf4j.Logger
import se.curity.identityserver.sdk.service.credential.PasswordTransformer
import se.curity.identityserver.sdk.service.credential.PasswordTransformer.MatchResult
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import java.util.Arrays

/**
 * What every memory-hard [PasswordTransformer] in this plugin does once a stored value has been decoded:
 * compute the hash under the [HashingLimiter], compare it in constant time, and decide whether the credential
 * needs rehashing. Only the parts that differ per algorithm are left to the subclasses — decoding the stored
 * value, the rules its decoder cannot judge (which Argon2 variant this transformer produces, for instance),
 * and comparing the decoded parameters with the configured ones.
 *
 * Every hash this plugin computes must go through [computeHash], which is what keeps the memory the algorithm
 * can use bounded by the per-hash memory times `max-concurrent-operations`, no matter how many verifications
 * arrive at the same time. [computeHashWithoutLimiter] is the one method that bypasses that bound, so it is
 * implemented by subclasses but called only from here. See [HashingLimiter] for the full rationale.
 *
 * @param Params the algorithm's public hashing parameters, as decoded from a stored password
 */
abstract class AbstractLimitedPasswordTransformer<Params>(
    private val limiter: HashingLimiter<*>,
) : PasswordTransformer {

    protected abstract val logger: Logger

    /**
     * Computes a hash without asking the limiter for a permit first. Never call this directly: it is the
     * unbounded computation [computeHash] exists to bound.
     */
    protected abstract fun computeHashWithoutLimiter(
        parameters: Params,
        password: CharSequence,
        hashLength: Int,
    ): ByteArray

    /**
     * Whether a stored password was produced with the settings this transformer is configured with now. When
     * it was not, a matching credential is reported as needing an upgrade, so that it is rehashed with the
     * current settings.
     */
    protected abstract fun matchesCurrentConfiguration(decodedParameters: Params, hashLength: Int): Boolean

    protected fun computeHash(parameters: Params, password: CharSequence, hashLength: Int): ByteArray {
        return limiter.hashing { computeHashWithoutLimiter(parameters, password, hashLength) }
    }

    /**
     * Encodes the password as UTF-8 without copying it into a `String`, which could not be cleared
     * afterwards. The caller clears the returned array.
     */
    protected fun utf8Bytes(password: CharSequence): ByteArray {
        val encoded = UTF_8.encode(CharBuffer.wrap(password))
        val bytes = ByteArray(encoded.remaining())
        encoded.get(bytes)

        if (encoded.hasArray()) {
            // The encoder's buffer holds the password too, and is not the caller's to clear.
            Arrays.fill(encoded.array(), 0)
        }

        return bytes
    }

    /**
     * Verifies a provided password against a decoded, stored one.
     *
     * @throws HashingUnavailableException if the server is at its limit of concurrent hashing operations,
     * which says nothing about whether the credential was correct. Every other failure to compute the hash is
     * reported as invalid stored data: no stored value may be able to turn a failed login into a server error.
     */
    protected fun matchDecoded(
        providedPassword: CharSequence,
        decodedParameters: Params,
        decodedHash: ByteArray,
    ): MatchResult {
        val computedHash = try {
            computeHash(decodedParameters, providedPassword, decodedHash.size)
        } catch (e: HashingUnavailableException) {
            throw e
        } catch (e: RuntimeException) {
            logger.debug("Problem computing password hash for a provided password: {}", e.toString())
            return MatchResult.NoMatch(true)
        }

        return matchHashes(computedHash, decodedParameters, decodedHash)
    }

    private fun matchHashes(
        computedHash: ByteArray,
        decodedParameters: Params,
        decodedHash: ByteArray,
    ): MatchResult = if (MessageDigest.isEqual(computedHash, decodedHash)) {
        logger.trace("Password match")
        // the length judged against the configured one is the stored hash's: that is the credential being
        // upgraded, and it is only incidentally the length the hash was just computed with
        MatchResult.Match(!matchesCurrentConfiguration(decodedParameters, decodedHash.size))
    } else {
        logger.trace("Stored password was valid but did not match the provided one")
        MatchResult.NoMatch()
    }
}
