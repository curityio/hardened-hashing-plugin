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

import io.curity.identityserver.plugin.credentials.hardenedhashing.AbstractLimitedPasswordTransformer
import io.curity.identityserver.plugin.credentials.hardenedhashing.getOrElse
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.service.credential.PasswordTransformer
import se.curity.identityserver.sdk.service.credential.PasswordTransformer.MatchResult
import java.security.SecureRandom
import java.util.Arrays
import org.bouncycastle.crypto.params.Argon2Parameters as BcArgon2Parameters

/**
 * A [PasswordTransformer] using one of the Argon2 variants, as defined by
 * [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).
 *
 * Transformed passwords are encoded using the PHC string format, see [Argon2PhcFormat], so they are
 * interchangeable with those produced by other Argon2 implementations.
 *
 * Hashing is memory-hard, and verification uses the parameters found in the *stored* password rather than the
 * configured ones. Both of those need care and are handled in two places: [Argon2PhcFormat.decode] and the
 * bounds in [Argon2Limits] reject stored values whose parameters this transformer will not compute, and
 * [Argon2HashingLimiter] caps how many hashes may be computed at once so that the memory they need stays
 * bounded no matter how many verifications arrive at the same time.
 */
sealed class Argon2PasswordTransformer(
    private val type: Argon2Type,
    private val configuration: Argon2Configuration,
    limiter: Argon2HashingLimiter,
) : AbstractLimitedPasswordTransformer<Argon2InputParameters>(limiter) {

    override val logger: Logger get() = _logger

    override fun transform(subject: String, providedPassword: CharSequence): String {
        val salt = ByteArray(configuration.saltLength).also(random::nextBytes)

        val parameters = Argon2InputParameters(
            type,
            CURRENT_VERSION,
            configuration.memoryCost,
            configuration.iterations,
            configuration.parallelism,
            salt
        )

        val hash = computeHash(parameters, providedPassword, configuration.hashLength)

        return Argon2PhcFormat.encode(Argon2Hash(parameters, hash))
    }

    override fun match(subject: String, providedPassword: CharSequence, transformedPassword: String): MatchResult {
        val decoded = Argon2PhcFormat.decode(transformedPassword).getOrElse { reason ->
            _logger.debug("Unable to decode a stored password hash: {}", reason)
            return MatchResult.NoMatch(true)
        }

        if (decoded.parameters.type != type) {
            _logger.debug(
                "A stored password hash was produced by {} rather than by {}",
                decoded.parameters.type.algorithmName, type.algorithmName
            )
            return MatchResult.NoMatch(true)
        }

        if (decoded.parameters.version != CURRENT_VERSION) {
            // BouncyCastle also supports version 0x10, but it is superseded and known to be weaker, so
            // credentials encoded with it are not accepted.
            _logger.debug(
                "A stored password hash uses Argon2 version {} rather than the current {}",
                decoded.parameters.version, CURRENT_VERSION
            )
            return MatchResult.NoMatch(true)
        }

        return matchDecoded(providedPassword, decoded.parameters, decoded.hash)
    }

    override fun matchesCurrentConfiguration(
        decodedParameters: Argon2InputParameters,
        hashLength: Int,
    ) = with(decodedParameters) {
        memoryCostInKibibytes == configuration.memoryCost &&
                iterations == configuration.iterations &&
                parallelism == configuration.parallelism &&
                salt.size == configuration.saltLength &&
                hashLength == configuration.hashLength
    }

    override fun computeHashWithoutLimiter(
        parameters: Argon2InputParameters,
        password: CharSequence,
        hashLength: Int,
    ): ByteArray {
        val bcParameters = BcArgon2Parameters.Builder(parameters.type.bouncyCastleType)
            .withVersion(parameters.version)
            .withMemoryAsKB(parameters.memoryCostInKibibytes)
            .withIterations(parameters.iterations)
            .withParallelism(parameters.parallelism)
            .withSalt(parameters.salt)
            .build()

        val generator = Argon2BytesGenerator().apply { init(bcParameters) }
        val hash = ByteArray(hashLength)
        val passwordBytes = utf8Bytes(password)

        try {
            generator.generateBytes(passwordBytes, hash)
        } finally {
            // BouncyCastle does not clear what it is given.
            Arrays.fill(passwordBytes, 0)
        }

        return hash
    }

    private companion object {
        /**
         * Version 0x13 (19) is the version defined by RFC 9106.
         */
        const val CURRENT_VERSION = BcArgon2Parameters.ARGON2_VERSION_13

        val random = SecureRandom()
        private val _logger = LoggerFactory.getLogger(Argon2PasswordTransformer::class.java)
    }
}

class Argon2idPasswordTransformer(configuration: Argon2Configuration, limiter: Argon2HashingLimiter) :
    Argon2PasswordTransformer(Argon2Type.ARGON2ID, configuration, limiter)

class Argon2iPasswordTransformer(configuration: Argon2Configuration, limiter: Argon2HashingLimiter) :
    Argon2PasswordTransformer(Argon2Type.ARGON2I, configuration, limiter)

class Argon2dPasswordTransformer(configuration: Argon2Configuration, limiter: Argon2HashingLimiter) :
    Argon2PasswordTransformer(Argon2Type.ARGON2D, configuration, limiter)
