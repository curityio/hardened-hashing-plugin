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

/**
 * The result of decoding a stored password hash.
 *
 * Not being able to decode one is an ordinary outcome rather than an error: a credential store may hold
 * hashes produced by another algorithm, by another implementation, or with parameters this plugin will not
 * compute. It is however indistinguishable from a wrong password in the server's logs unless the reason is
 * carried out of the decoder, which is what [Invalid] is for.
 *
 * A reason is written for whoever reads those logs. It names the field at fault, and for values that parsed
 * as numbers the bound they fell outside of, but never repeats any part of the stored value itself: that
 * value is untrusted input, and the salt and the hash are not the server's to log.
 */
sealed interface PhcDecodeResult<out T> {

    data class Decoded<T>(val value: T) : PhcDecodeResult<T>

    data class Invalid(val reason: String) : PhcDecodeResult<Nothing>
}

/**
 * The decoded value, or the result of applying [onInvalid] to the reason. [onInvalid] cannot produce a value
 * of its own and therefore returns from the calling function or throws.
 */
inline fun <T> PhcDecodeResult<T>.getOrElse(onInvalid: (reason: String) -> Nothing): T =
    when (this) {
        is PhcDecodeResult.Decoded -> value
        is PhcDecodeResult.Invalid -> onInvalid(reason)
    }
