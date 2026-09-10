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

import se.curity.identityserver.sdk.plugin.descriptor.PasswordTransformerPluginDescriptor
import se.curity.identityserver.sdk.service.credential.PasswordTransformer
import java.util.Optional

/**
 * Provides scrypt as a password hashing algorithm.
 *
 * scrypt has its own descriptor, separate from the Argon2 one in this plugin, because the two algorithm
 * families have different cost parameters and a descriptor's configuration is what every algorithm it
 * provides is configured with.
 */
class ScryptPasswordTransformerPluginDescriptor : PasswordTransformerPluginDescriptor<ScryptConfiguration> {

    override fun getPluginImplementationType(): String = "scrypt-password-transformer"

    override fun getConfigurationType(): Class<ScryptConfiguration> = ScryptConfiguration::class.java

    /**
     * The limit on concurrent hashing has to outlive the transformers, which are created per credential
     * verification, so it lives in the managed object.
     */
    override fun createManagedObject(configuration: ScryptConfiguration): Optional<ScryptHashingLimiter> =
        Optional.of(ScryptHashingLimiter(configuration))

    override fun getPasswordTransformers(): Map<String, Class<out PasswordTransformer>> = mapOf(
        ScryptPhcFormat.ALGORITHM_NAME to ScryptPasswordTransformer::class.java,
    )
}
