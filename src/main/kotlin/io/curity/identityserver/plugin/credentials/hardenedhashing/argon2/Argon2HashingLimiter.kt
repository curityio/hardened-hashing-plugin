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

import io.curity.identityserver.plugin.credentials.hardenedhashing.HashingLimiter

/**
 * Bounds how many Argon2 hashes may be computed at the same time: computing one hash allocates
 * `memory-cost` kibibytes on the Java heap and holds it until the hash is done, so with this limiter in
 * place the memory Argon2 can use is at most `memory-cost * max-concurrent-operations`. See [HashingLimiter]
 * for the full rationale.
 */
class Argon2HashingLimiter(configuration: Argon2Configuration) :
    HashingLimiter<Argon2Configuration>(configuration, configuration.maxConcurrentOperations, "Argon2")
