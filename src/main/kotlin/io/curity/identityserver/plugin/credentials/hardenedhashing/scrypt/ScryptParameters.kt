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

/**
 * The public parameters of a scrypt computation, as defined by
 * [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html). Together with the password, they fully determine
 * the hash, so all of them are encoded in the stored password.
 *
 * The CPU/memory cost is carried as its base-2 logarithm ([costExponent], the `ln` of the PHC string format),
 * which is also what makes N a power of two by construction.
 */
data class ScryptInputParameters(
    val costExponent: Int,
    val blockSize: Int,
    val parallelization: Int,
    val salt: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ScryptInputParameters) return false

        return costExponent == other.costExponent &&
                blockSize == other.blockSize &&
                parallelization == other.parallelization &&
                salt.contentEquals(other.salt)
    }

    override fun hashCode(): Int {
        var result = costExponent
        result = 31 * result + blockSize
        result = 31 * result + parallelization
        result = 31 * result + salt.contentHashCode()
        return result
    }

    override fun toString() =
        "ScryptInputParameters(costExponent=$costExponent, blockSize=$blockSize, " +
                "parallelization=$parallelization, saltLength=${salt.size})"
}

/**
 * A scrypt hash together with the parameters used to compute it.
 */
data class ScryptHash(val parameters: ScryptInputParameters, val hash: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ScryptHash) return false

        return parameters == other.parameters && hash.contentEquals(other.hash)
    }

    override fun hashCode() = 31 * parameters.hashCode() + hash.contentHashCode()

    override fun toString() = "ScryptHash(parameters=$parameters, hashLength=${hash.size})"
}
