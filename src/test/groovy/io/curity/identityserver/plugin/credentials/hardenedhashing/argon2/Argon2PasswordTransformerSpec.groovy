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

import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import se.curity.identityserver.sdk.service.credential.PasswordTransformer.MatchResult
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.StandardCharsets
import java.util.Arrays

class Argon2PasswordTransformerSpec extends Specification {
    // deliberately cheap so that the tests are fast; the interop test below uses the real parameters
    static final int MEMORY_COST = 256
    static final int ITERATIONS = 1
    static final int PARALLELISM = 1
    static final int SALT_LENGTH = 16
    static final int HASH_LENGTH = 32
    static final int MAX_CONCURRENT_OPERATIONS = 4

    // a 16 byte salt and a 32 byte hash, both base64 encoded without padding, for hand-written stored values
    static final String SALT_B64 = "c29tZXNhbHQxMjM0NTY3OA"
    static final String HASH_B64 = "c29tZWhhc2gxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy"

    static Argon2Configuration configuration(Map overrides = [:]) {
        def values = [
                memoryCost             : MEMORY_COST,
                iterations             : ITERATIONS,
                parallelism            : PARALLELISM,
                saltLength             : SALT_LENGTH,
                hashLength             : HASH_LENGTH,
                maxConcurrentOperations: MAX_CONCURRENT_OPERATIONS,
        ] + overrides

        return new Argon2Configuration() {
            String id() { "argon2" }

            int getMemoryCost() { values.memoryCost }

            int getIterations() { values.iterations }

            int getParallelism() { values.parallelism }

            int getSaltLength() { values.saltLength }

            int getHashLength() { values.hashLength }

            int getMaxConcurrentOperations() { values.maxConcurrentOperations }
        }
    }

    static Argon2idPasswordTransformer argon2id(Map overrides = [:]) {
        def config = configuration(overrides)
        return new Argon2idPasswordTransformer(config, new Argon2HashingLimiter(config))
    }

    def "transform encodes the algorithm and the configured parameters"() {
        given:
        def transformer = argon2id()

        when:
        def transformed = transformer.transform('user-1', "s3cret")

        then:
        def decoded = decode(transformed)
        decoded != null

        and:
        decoded.parameters.type == Argon2Type.ARGON2ID
        decoded.parameters.version == 0x13
        decoded.parameters.memoryCostInKibibytes == MEMORY_COST
        decoded.parameters.iterations == ITERATIONS
        decoded.parameters.parallelism == PARALLELISM
        decoded.parameters.salt.length == SALT_LENGTH
        decoded.hash.length == HASH_LENGTH

        and: 'the encoded value uses the PHC string format'
        transformed.startsWith("\$argon2id\$v=19\$m=$MEMORY_COST,t=$ITERATIONS,p=$PARALLELISM\$")
    }

    def "transform generates a new salt every time"() {
        given:
        def transformer = argon2id()

        expect:
        transformer.transform('user-1', "s3cret") != transformer.transform('user-1', "s3cret")
    }

    @Unroll
    def "#algorithm matches the password it transformed"() {
        given:
        def transformer = transformerFor(algorithm)

        when:
        def transformed = transformer.transform('user-1', "s3cret")

        then:
        transformer.match('user-1', "s3cret", transformed) == new MatchResult.Match(false)

        where:
        algorithm << ["argon2id", "argon2i", "argon2d"]
    }

    def "a wrong password does not match, and the stored data is not reported as invalid"() {
        given:
        def transformer = argon2id()
        def transformed = transformer.transform('user-1', "s3cret")

        expect:
        transformer.match('user-1', "wrong", transformed) == new MatchResult.NoMatch(false)
    }

    @Unroll
    def "a stored value that is not an argon2id hash is reported as invalid data: #description"() {
        given:
        def transformer = argon2id()

        expect:
        transformer.match('user-1', "s3cret", storedValue) == new MatchResult.NoMatch(true)

        where:
        description                      | storedValue
        'empty'                          | ''
        'plaintext'                      | 's3cret'
        'bcrypt'                         | '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
        'sha-crypt'                      | '$5$rounds=20000$abcdefgh$xxxx'
        'unknown argon2 variant'         | '$argon2z$v=19$m=256,t=1,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'another argon2 variant'         | '$argon2i$v=19$m=256,t=1,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'superseded argon2 version 0x10' | '$argon2id$v=16$m=256,t=1,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'missing the hash'               | '$argon2id$v=19$m=256,t=1,p=1$c29tZXNhbHQ'
        'empty salt'                     | '$argon2id$v=19$m=256,t=1,p=1$$c29tZWhhc2g'
        'non-numeric memory cost'        | '$argon2id$v=19$m=lots,t=1,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'missing the parallelism'        | '$argon2id$v=19$m=256,t=1$c29tZXNhbHQ$c29tZWhhc2g'
        'a duplicated parameter'         | '$argon2id$v=19$m=256,m=256,t=1$c29tZXNhbHQ$c29tZWhhc2g'
        'a duplicate of a zero'          | '$argon2id$v=19$m=0,m=256,t=1$c29tZXNhbHQ$c29tZWhhc2g'
        'not base64'                     | '$argon2id$v=19$m=256,t=1,p=1$not base64!$c29tZWhhc2g'
        'memory cost below 8 per lane'   | '$argon2id$v=19$m=16,t=1,p=4$c29tZXNhbHQ$c29tZWhhc2g'
    }

    /**
     * Stored passwords are untrusted input: whatever they ask for, verification must answer "not a hash I can
     * verify" rather than throwing or allocating without bound. Every case here made an earlier version of
     * this plugin throw an IllegalStateException or an OutOfMemoryError.
     */
    @Unroll
    def "a stored value with out of range parameters is rejected rather than computed: #description"() {
        given:
        def transformer = argon2id()

        when:
        def result = transformer.match('user-1', "s3cret", storedValue)

        then:
        noExceptionThrown()

        and:
        result == new MatchResult.NoMatch(true)

        where:
        description                                          | storedValue
        'a hash shorter than argon2 allows'                  | "\$argon2id\$v=19\$m=256,t=1,p=1\$$SALT_B64\$AA"
        'a hash longer than any this plugin produces'        | "\$argon2id\$v=19\$m=256,t=1,p=1\$$SALT_B64\$${'A' * 4000}"
        'a salt shorter than argon2 allows'                  | "\$argon2id\$v=19\$m=256,t=1,p=1\$YWJj\$$HASH_B64"
        'a salt longer than any this plugin produces'        | "\$argon2id\$v=19\$m=256,t=1,p=1\$${'A' * 4000}\$$HASH_B64"
        'a parallelism that overflows the memory cost check' | "\$argon2id\$v=19\$m=256,t=1,p=300000000\$$SALT_B64\$$HASH_B64"
        'a parallelism above what argon2 supports'           | "\$argon2id\$v=19\$m=2000000000,t=1,p=20000000\$$SALT_B64\$$HASH_B64"
        'a memory cost that would exhaust the heap'          | "\$argon2id\$v=19\$m=2000000000,t=1,p=1\$$SALT_B64\$$HASH_B64"
        'a memory cost just above the maximum'               | "\$argon2id\$v=19\$m=1048577,t=1,p=1\$$SALT_B64\$$HASH_B64"
        'an iteration count that would never finish'         | "\$argon2id\$v=19\$m=256,t=2000000000,p=1\$$SALT_B64\$$HASH_B64"
        'an iteration count just above the maximum'          | "\$argon2id\$v=19\$m=256,t=129,p=1\$$SALT_B64\$$HASH_B64"
    }

    /**
     * The reason is what the transformer logs when a stored value is rejected, which is the only way to tell
     * a hash that could not be verified from a wrong password. It must never repeat any part of the stored
     * value, so the untrusted fields (the algorithm, the parameter names, the salt and the hash) are only
     * ever named, not echoed.
     */
    @Unroll
    def "the decoder reports why a stored value is not an Argon2 hash: #description"() {
        when:
        def result = Argon2PhcFormat.INSTANCE.decode(storedValue)

        then:
        result instanceof PhcDecodeResult.Invalid

        and:
        result.reason.contains(expectedReason)

        where:
        description                    | storedValue                                                     || expectedReason
        'plaintext'                    | 's3cret'                                                        || 'not a PHC string'
        'another algorithm'            | "\$argon2z\$v=19\$m=256,t=1,p=1\$$SALT_B64\$$HASH_B64"          || 'not one of the Argon2 variants'
        'a missing version'            | "\$argon2id\$m=256,t=1,p=1\$$SALT_B64\$$HASH_B64\$x"            || "the 'v' field is missing"
        'a missing parameter'          | "\$argon2id\$v=19\$m=256,t=1\$$SALT_B64\$$HASH_B64"             || "the 'p' parameter is missing"
        'a duplicated parameter'       | "\$argon2id\$v=19\$m=256,m=256,t=1\$$SALT_B64\$$HASH_B64"       || "the 'm' parameter appears more than once"
        'a non-numeric parameter'      | "\$argon2id\$v=19\$m=lots,t=1,p=1\$$SALT_B64\$$HASH_B64"        || "the 'm' parameter is not a number"
        'an unknown parameter'         | "\$argon2id\$v=19\$m=256,t=1,x=1\$$SALT_B64\$$HASH_B64"         || 'an unknown cost parameter'
        'a parallelism out of range'   | "\$argon2id\$v=19\$m=256,t=1,p=20000000\$$SALT_B64\$$HASH_B64"  || 'p=20000000 is outside the accepted 1..255'
        'a zero iteration count'       | "\$argon2id\$v=19\$m=256,t=0,p=1\$$SALT_B64\$$HASH_B64"         || 't=0 is outside the accepted 1..128'
        'an iteration count too high'  | "\$argon2id\$v=19\$m=256,t=129,p=1\$$SALT_B64\$$HASH_B64"       || 't=129 is outside the accepted 1..128'
        'a memory cost too high'       | "\$argon2id\$v=19\$m=1048577,t=1,p=1\$$SALT_B64\$$HASH_B64"     || 'm=1048577 is more than the 1048576 kibibytes'
        'memory cost below 8 per lane' | "\$argon2id\$v=19\$m=16,t=1,p=4\$$SALT_B64\$$HASH_B64"          || 'm=16 is below the 8 kibibytes per lane'
        'a salt that is not base64'    | "\$argon2id\$v=19\$m=256,t=1,p=1\$not base64!\$$HASH_B64"       || 'the salt is not valid base64'
        'a hash that is not base64'    | "\$argon2id\$v=19\$m=256,t=1,p=1\$$SALT_B64\$not base64!"       || 'the hash is not valid base64'
        'a salt shorter than accepted' | "\$argon2id\$v=19\$m=256,t=1,p=1\$YWJj\$$HASH_B64"              || 'the salt length 3 is outside'
        'a hash shorter than accepted' | "\$argon2id\$v=19\$m=256,t=1,p=1\$$SALT_B64\$AA"                || 'the hash length 1 is outside'
    }

    def "the reported reason repeats no part of the stored value"() {
        given: 'a stored value whose untrusted fields are all recognisable'
        def storedValue = '$argon2id$v=19$m=256,unknownparameter=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo'

        when:
        def result = Argon2PhcFormat.INSTANCE.decode(storedValue)

        then:
        result instanceof PhcDecodeResult.Invalid

        and:
        ['unknownparameter', 'c2FsdHNhbHRzYWx0', 'aGFzaGhhc2hoYXNo'].every {
            !result.reason.contains(it)
        }
    }

    @Unroll
    def "a stored value with parameters at the limit is still accepted: #description"() {
        // asserted through the decoder rather than through match(), because actually hashing with these
        // parameters would allocate a gibibyte or run for a very long time
        expect:
        Argon2PhcFormat.INSTANCE.decode(storedValue) instanceof PhcDecodeResult.Decoded

        where:
        description                   | storedValue
        'the highest memory cost'     | "\$argon2id\$v=19\$m=1048576,t=1,p=1\$$SALT_B64\$$HASH_B64"
        'the highest iteration count' | "\$argon2id\$v=19\$m=256,t=128,p=1\$$SALT_B64\$$HASH_B64"
        'the shortest allowed salt'   | "\$argon2id\$v=19\$m=256,t=1,p=1\$c29tZXNhbHQ\$$HASH_B64"
        'the shortest allowed hash'   | "\$argon2id\$v=19\$m=256,t=1,p=1\$$SALT_B64\$AAAAAA"
    }

    @Unroll
    def "a match with outdated parameters requests an upgrade: #description"() {
        given: 'a password transformed with the original settings'
        def transformed = argon2id().transform('user-1', "s3cret")

        and: 'a transformer with updated settings'
        def transformer = argon2id(overrides)

        expect:
        transformer.match('user-1', "s3cret", transformed) == new MatchResult.Match(true)

        where:
        description        | overrides
        'more memory'      | [memoryCost: MEMORY_COST * 2]
        'more iterations'  | [iterations: ITERATIONS + 1]
        'more parallelism' | [parallelism: PARALLELISM + 1]
        'a longer salt'    | [saltLength: SALT_LENGTH * 2]
        'a longer hash'    | [hashLength: HASH_LENGTH * 2]
    }

    @Unroll
    def "#algorithm computes the same hash as a plain BouncyCastle computation"() {
        given:
        def transformer = transformerFor(algorithm)

        when: 'a password is transformed'
        def transformed = transformer.transform('user-1', "s3cret")
        def decoded = decode(transformed)

        and: 'the same hash is computed independently of the code under test'
        def expectedHash = argon2(
                Argon2Type.fromAlgorithmName(algorithm).bouncyCastleType,
                decoded.parameters.salt,
                "s3cret",
                HASH_LENGTH)

        then:
        Arrays.equals(decoded.hash, expectedHash)

        where:
        algorithm << ["argon2id", "argon2i", "argon2d"]
    }

    @Unroll
    def "a #description password read from a CharSequence is encoded like the same String"() {
        given:
        def transformer = argon2id()

        when: 'the password is transformed from a sequence that is not a String, which is then cleared'
        def sequence = new StringBuilder(password)
        def transformed = transformer.transform('user-1', sequence)
        sequence.length().times { sequence.setCharAt(it, ' ' as char) }

        and: 'the same hash is computed independently, from the password as a String'
        def decoded = decode(transformed)
        def expectedHash = argon2(
                Argon2Type.ARGON2ID.bouncyCastleType,
                decoded.parameters.salt,
                password,
                HASH_LENGTH)

        then: 'the hashes are the same, so the sequence was read exactly like the String'
        Arrays.equals(decoded.hash, expectedHash)

        and: 'the password matches, given either as a String or as another CharSequence'
        transformer.matches('user-1', password, transformed)
        transformer.matches('user-1', new StringBuilder(password), transformed)

        where:
        description | password
        'ASCII'     | 's3cret'
        'accented'  | 'p\u00e4ssw\u00f6rd'
        'emoji'     | 'p4ss\ud83d\udd10word'
        'CJK'       | '\u5bc6\u7801\u5bc6\u7801'
        'empty'     | ''
    }

    def "hashes produced by the argon2 reference implementation are accepted"() {
        given: 'the example from the argon2 reference implementation README'
        // echo -n "password" | ./argon2 somesalt -t 2 -m 16 -p 4
        def transformed = '$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4'

        and: 'a transformer configured just like the reference implementation was'
        def config = configuration(
                memoryCost: 65536, iterations: 2, parallelism: 4, saltLength: 8, hashLength: 32)
        def transformer = new Argon2iPasswordTransformer(config, new Argon2HashingLimiter(config))

        expect:
        transformer.match('user-1', "password", transformed) == new MatchResult.Match(false)

        and:
        transformer.match('user-1', "wrong", transformed) == new MatchResult.NoMatch(false)
    }

    private static Argon2Hash decode(String encoded) {
        def result = Argon2PhcFormat.INSTANCE.decode(encoded)
        assert result instanceof PhcDecodeResult.Decoded: "not decoded: $result"
        return result.value
    }

    private static transformerFor(String algorithm) {
        def config = configuration()
        def limiter = new Argon2HashingLimiter(config)

        switch (algorithm) {
            case "argon2id": return new Argon2idPasswordTransformer(config, limiter)
            case "argon2i": return new Argon2iPasswordTransformer(config, limiter)
            case "argon2d": return new Argon2dPasswordTransformer(config, limiter)
            default: throw new IllegalArgumentException(algorithm)
        }
    }

    private static byte[] argon2(int type, byte[] salt, String password, int hashLength) {
        def parameters = new Argon2Parameters.Builder(type)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(MEMORY_COST)
                .withIterations(ITERATIONS)
                .withParallelism(PARALLELISM)
                .withSalt(salt)
                .build()

        def generator = new Argon2BytesGenerator()
        generator.init(parameters)

        byte[] hash = new byte[hashLength]
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), hash)

        return hash
    }
}
