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

import io.curity.identityserver.plugin.credentials.hardenedhashing.AbstractLimitedPasswordTransformer
import io.curity.identityserver.plugin.credentials.hardenedhashing.getOrElse
import org.bouncycastle.crypto.generators.SCrypt
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.service.credential.PasswordTransformer
import se.curity.identityserver.sdk.service.credential.PasswordTransformer.MatchResult
import java.security.SecureRandom
import java.util.Arrays

/**
 * A [PasswordTransformer] using scrypt, as defined by
 * [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html).
 *
 * Transformed passwords are encoded using the PHC string format, see [ScryptPhcFormat], so they are
 * interchangeable with those produced by other scrypt implementations.
 *
 * Hashing is memory-hard, and verification uses the parameters found in the *stored* password rather than the
 * configured ones. Both of those need care and are handled in two places: [ScryptPhcFormat.decode] and the
 * bounds in [ScryptLimits] reject stored values whose parameters this transformer will not compute, and
 * [ScryptHashingLimiter] caps how many hashes may be computed at once so that the memory they need stays
 * bounded no matter how many verifications arrive at the same time.
 */
class ScryptPasswordTransformer(
    private val configuration: ScryptConfiguration,
    limiter: ScryptHashingLimiter,
) : AbstractLimitedPasswordTransformer<ScryptInputParameters>(limiter) {

    override val logger: Logger get() = _logger

    override fun transform(subject: String, providedPassword: CharSequence): String {
        val salt = ByteArray(configuration.saltLength).also(random::nextBytes)

        val parameters = ScryptInputParameters(
            configuration.costExponent,
            configuration.blockSize,
            configuration.parallelization,
            salt
        )

        val hash = computeHash(parameters, providedPassword, configuration.hashLength)

        return ScryptPhcFormat.encode(ScryptHash(parameters, hash))
    }

    override fun match(subject: String, providedPassword: CharSequence, transformedPassword: String): MatchResult {
        // Not a scrypt hash this transformer could verify, so it cannot have been produced by it. Reporting
        // invalid data allows the credential manager to try the algorithms configured for rehashing. All
        // parameter bounds are enforced by the decoder, see ScryptPhcFormat and ScryptLimits.
        val decoded = ScryptPhcFormat.decode(transformedPassword).getOrElse { reason ->
            _logger.debug("Unable to decode a stored password hash: {}", reason)
            return MatchResult.NoMatch(true)
        }

        return matchDecoded(providedPassword, decoded.parameters, decoded.hash)
    }

    override fun matchesCurrentConfiguration(
        decodedParameters: ScryptInputParameters,
        hashLength: Int,
    ): Boolean = with(decodedParameters) {
        costExponent == configuration.costExponent &&
                blockSize == configuration.blockSize &&
                parallelization == configuration.parallelization &&
                salt.size == configuration.saltLength &&
                hashLength == configuration.hashLength
    }

    override fun computeHashWithoutLimiter(
        parameters: ScryptInputParameters,
        password: CharSequence,
        hashLength: Int,
    ): ByteArray {
        val passwordBytes = utf8Bytes(password)

        try {
            return SCrypt.generate(
                passwordBytes,
                parameters.salt,
                1 shl parameters.costExponent,
                parameters.blockSize,
                parameters.parallelization,
                hashLength
            )
        } finally {
            // BouncyCastle does not clear what it is given.
            Arrays.fill(passwordBytes, 0)
        }
    }

    private companion object {
        val random = SecureRandom()
        private val _logger = LoggerFactory.getLogger(ScryptPasswordTransformer::class.java)
    }
}
