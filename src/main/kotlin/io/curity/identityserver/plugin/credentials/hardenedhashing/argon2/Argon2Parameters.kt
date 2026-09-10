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

import org.bouncycastle.crypto.params.Argon2Parameters as BcArgon2Parameters

/**
 * The Argon2 variants, as defined by [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1).
 *
 * The [algorithmName] is both the name of the algorithm in the server's configuration and the identifier used
 * in the encoded password, so it must match the names used by other Argon2 implementations.
 */
enum class Argon2Type(val algorithmName: String, val bouncyCastleType: Int) {
    /**
     * Data-independent memory access, resistant to side-channel attacks.
     */
    ARGON2I("argon2i", BcArgon2Parameters.ARGON2_i),

    /**
     * Data-dependent memory access, resistant to GPU cracking attacks.
     */
    ARGON2D("argon2d", BcArgon2Parameters.ARGON2_d),

    /**
     * A hybrid of Argon2i and Argon2d. This is the variant recommended by RFC 9106 for password hashing.
     */
    ARGON2ID("argon2id", BcArgon2Parameters.ARGON2_id),
    ;

    companion object {
        private val byAlgorithmName = entries.associateBy { it.algorithmName }

        @JvmStatic
        fun fromAlgorithmName(algorithmName: String): Argon2Type? = byAlgorithmName[algorithmName]
    }
}

/**
 * The public parameters of an Argon2 computation. Together with the password, they fully determine the hash,
 * so all of them are encoded in the stored password.
 */
data class Argon2InputParameters(
    val type: Argon2Type,
    val version: Int,
    val memoryCostInKibibytes: Int,
    val iterations: Int,
    val parallelism: Int,
    val salt: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Argon2InputParameters) return false

        return type == other.type &&
                version == other.version &&
                memoryCostInKibibytes == other.memoryCostInKibibytes &&
                iterations == other.iterations &&
                parallelism == other.parallelism &&
                salt.contentEquals(other.salt)
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + version
        result = 31 * result + memoryCostInKibibytes
        result = 31 * result + iterations
        result = 31 * result + parallelism
        result = 31 * result + salt.contentHashCode()
        return result
    }

    override fun toString() =
        "Argon2InputParameters(type=$type, version=$version, memoryCostInKibibytes=$memoryCostInKibibytes, " +
                "iterations=$iterations, parallelism=$parallelism, saltLength=${salt.size})"
}
