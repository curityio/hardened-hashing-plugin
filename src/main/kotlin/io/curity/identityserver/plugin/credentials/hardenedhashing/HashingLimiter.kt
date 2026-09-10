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

import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.plugin.ManagedObject
import java.time.Duration
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

/**
 * Bounds how many hashes of a memory-hard algorithm may be computed at the same time.
 *
 * The algorithms this plugin provides are memory-hard by design: computing one hash allocates a large,
 * configuration-determined amount of memory on the Java heap and holds it until the hash is done. Nothing
 * else bounds how many credential verifications run concurrently, so without a limit the heap needed is that
 * amount times the size of the HTTP thread pool, and an unauthenticated caller can drive the node into GC
 * thrash simply by opening parallel authentication requests. With this limiter in place the memory a password
 * transformer can use is at most the per-hash memory times `max-concurrent-operations`. The per-hash memory
 * is the configured one only when hashing a new password: verification uses the parameters recorded in the
 * stored value, which may be heavier than any this plugin can be configured with — the decoders accept them
 * up to a plugin-wide ceiling of 1 GiB. Where stored values may come from elsewhere, that ceiling is the
 * per-hash memory to size against.
 *
 * A [ManagedObject] is the natural home for it: a new [PasswordTransformer][se.curity.identityserver.sdk.service.credential.PasswordTransformer]
 * instance is created for every credential verification, so the limit has to live in something whose lifetime
 * is the plugin's configuration. The server creates one instance per configured password transformer and
 * closes it when the configuration changes, which also means the limit is per password transformer rather
 * than server wide: credential managers sharing a password transformer share its limit.
 *
 * @param algorithmFamily the name of the hashing algorithm family, used in error messages
 */
abstract class HashingLimiter<C : Configuration>(
    configuration: C,
    maxConcurrentOperations: Int,
    private val algorithmFamily: String,
) : ManagedObject<C>(configuration) {

    // Fair, so that a steady stream of new requests cannot starve one that is already waiting.
    private val _permits = Semaphore(maxConcurrentOperations, true)

    /**
     * Runs [operation] once a permit is available.
     *
     * @throws HashingUnavailableException if no permit becomes available within [WAIT_TIMEOUT], which
     * means the server is overloaded. Failing is deliberate: reporting the credential as not matching would
     * turn an overload into a wrong authentication decision.
     */
    fun <T> hashing(operation: () -> T): T {
        try {
            if (!_permits.tryAcquire(WAIT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                throw HashingUnavailableException(
                    "Timed out after $WAIT_TIMEOUT waiting to compute a $algorithmFamily hash. The " +
                            "configured limit of concurrent $algorithmFamily operations may be too low " +
                            "for the load on this server."
                )
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw HashingUnavailableException(
                "Interrupted while waiting to compute a $algorithmFamily hash", e
            )
        }

        try {
            return operation()
        } finally {
            _permits.release()
        }
    }

    private companion object {
        /**
         * How long a credential verification waits for its turn before giving up. Long enough that it is never
         * reached under a load the server can actually serve, short enough that a request thread is not held
         * indefinitely.
         */
        val WAIT_TIMEOUT: Duration = Duration.ofSeconds(30)
    }
}

/**
 * Thrown when a hash could not be computed because the server is at its limit of concurrent hashing
 * operations. This says nothing about whether the credential was correct.
 */
class HashingUnavailableException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)
