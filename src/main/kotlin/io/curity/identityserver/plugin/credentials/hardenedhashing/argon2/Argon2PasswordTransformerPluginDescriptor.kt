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

import se.curity.identityserver.sdk.plugin.descriptor.PasswordTransformerPluginDescriptor
import se.curity.identityserver.sdk.service.credential.PasswordTransformer
import java.util.Optional

/**
 * Provides the three Argon2 variants as password hashing algorithms.
 */
class Argon2PasswordTransformerPluginDescriptor : PasswordTransformerPluginDescriptor<Argon2Configuration> {

    override fun getPluginImplementationType(): String = "argon2-password-transformer"

    override fun getConfigurationType(): Class<Argon2Configuration> = Argon2Configuration::class.java

    /**
     * The limit on concurrent hashing has to outlive the transformers, which are created per credential
     * verification, so it lives in the managed object.
     */
    override fun createManagedObject(configuration: Argon2Configuration): Optional<Argon2HashingLimiter> =
        Optional.of(Argon2HashingLimiter(configuration))

    override fun getPasswordTransformers(): Map<String, Class<out PasswordTransformer>> = mapOf(
        Argon2Type.ARGON2ID.algorithmName to Argon2idPasswordTransformer::class.java,
        Argon2Type.ARGON2I.algorithmName to Argon2iPasswordTransformer::class.java,
        Argon2Type.ARGON2D.algorithmName to Argon2dPasswordTransformer::class.java,
    )
}
