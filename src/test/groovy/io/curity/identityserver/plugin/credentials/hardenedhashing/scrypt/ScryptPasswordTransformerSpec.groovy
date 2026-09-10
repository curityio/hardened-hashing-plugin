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

import io.curity.identityserver.plugin.credentials.hardenedhashing.PhcDecodeResult
import org.bouncycastle.crypto.generators.SCrypt
import se.curity.identityserver.sdk.service.credential.PasswordTransformer.MatchResult
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.StandardCharsets

class ScryptPasswordTransformerSpec extends Specification {
    // deliberately cheap so that the tests are fast; the interop tests below use real parameters
    static final int COST_EXPONENT = 4
    static final int BLOCK_SIZE = 8
    static final int PARALLELIZATION = 1
    static final int SALT_LENGTH = 16
    static final int HASH_LENGTH = 32
    static final int MAX_CONCURRENT_OPERATIONS = 4

    // a 16 byte salt and a 32 byte hash, both base64 encoded without padding, for hand-written stored values
    static final String SALT_B64 = "c29tZXNhbHQxMjM0NTY3OA"
    static final String HASH_B64 = "c29tZWhhc2gxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy"

    static ScryptConfiguration configuration(Map overrides = [:]) {
        def values = [
                costExponent           : COST_EXPONENT,
                blockSize              : BLOCK_SIZE,
                parallelization        : PARALLELIZATION,
                saltLength             : SALT_LENGTH,
                hashLength             : HASH_LENGTH,
                maxConcurrentOperations: MAX_CONCURRENT_OPERATIONS,
        ] + overrides

        return new ScryptConfiguration() {
            String id() { "scrypt" }

            int getCostExponent() { values.costExponent }

            int getBlockSize() { values.blockSize }

            int getParallelization() { values.parallelization }

            int getSaltLength() { values.saltLength }

            int getHashLength() { values.hashLength }

            int getMaxConcurrentOperations() { values.maxConcurrentOperations }
        }
    }

    static ScryptPasswordTransformer scrypt(Map overrides = [:]) {
        def config = configuration(overrides)
        return new ScryptPasswordTransformer(config, new ScryptHashingLimiter(config))
    }

    def "transform encodes the algorithm and the configured parameters"() {
        given:
        def transformer = scrypt()

        when:
        def transformed = transformer.transform('user-1', "s3cret")

        then:
        def decoded = decode(transformed)
        decoded != null

        and:
        decoded.parameters.costExponent == COST_EXPONENT
        decoded.parameters.blockSize == BLOCK_SIZE
        decoded.parameters.parallelization == PARALLELIZATION
        decoded.parameters.salt.length == SALT_LENGTH
        decoded.hash.length == HASH_LENGTH

        and: 'the encoded value uses the PHC string format'
        transformed.startsWith("\$scrypt\$ln=$COST_EXPONENT,r=$BLOCK_SIZE,p=$PARALLELIZATION\$")
    }

    def "transform generates a new salt every time"() {
        given:
        def transformer = scrypt()

        expect:
        transformer.transform('user-1', "s3cret") != transformer.transform('user-1', "s3cret")
    }

    def "scrypt matches the password it transformed"() {
        given:
        def transformer = scrypt()

        when:
        def transformed = transformer.transform('user-1', "s3cret")

        then:
        transformer.match('user-1', "s3cret", transformed) == new MatchResult.Match(false)
    }

    def "a wrong password does not match, and the stored data is not reported as invalid"() {
        given:
        def transformer = scrypt()
        def transformed = transformer.transform('user-1', "s3cret")

        expect:
        transformer.match('user-1', "wrong", transformed) == new MatchResult.NoMatch(false)
    }

    @Unroll
    def "a stored value that is not a scrypt hash is reported as invalid data: #description"() {
        given:
        def transformer = scrypt()

        expect:
        transformer.match('user-1', "s3cret", storedValue) == new MatchResult.NoMatch(true)

        where:
        description                | storedValue
        'empty'                    | ''
        'plaintext'                | 's3cret'
        'bcrypt'                   | '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
        'argon2id'                 | '$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'unix scrypt crypt format' | '$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D'
        'unknown algorithm'        | '$scrypt2$ln=4,r=8,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'missing the hash'         | '$scrypt$ln=4,r=8,p=1$c29tZXNhbHQ'
        'an extra segment'         | "\$scrypt\$ln=4,r=8,p=1\$$SALT_B64\$$HASH_B64\$extra"
        'empty salt'               | '$scrypt$ln=4,r=8,p=1$$c29tZWhhc2g'
        'non-numeric cost'         | '$scrypt$ln=lots,r=8,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'missing the block size'   | '$scrypt$ln=4,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'a duplicated parameter'   | '$scrypt$ln=4,ln=4,r=8$c29tZXNhbHQ$c29tZWhhc2g'
        'a duplicate of a zero'    | '$scrypt$ln=0,ln=4,r=8$c29tZXNhbHQ$c29tZWhhc2g'
        'an unknown parameter'     | '$scrypt$ln=4,r=8,x=1$c29tZXNhbHQ$c29tZWhhc2g'
        'the plain N parameter'    | '$scrypt$N=16,r=8,p=1$c29tZXNhbHQ$c29tZWhhc2g'
        'not base64'               | '$scrypt$ln=4,r=8,p=1$not base64!$c29tZWhhc2g'
    }

    /**
     * Stored passwords are untrusted input: whatever they ask for, verification must answer "not a hash I can
     * verify" rather than throwing or allocating without bound. The bounds are the scrypt equivalents of the
     * ones the Argon2 transformer applies, see ScryptLimits.
     */
    @Unroll
    def "a stored value with out of range parameters is rejected rather than computed: #description"() {
        given:
        def transformer = scrypt()

        when:
        def result = transformer.match('user-1', "s3cret", storedValue)

        then:
        noExceptionThrown()

        and:
        result == new MatchResult.NoMatch(true)

        where:
        description                                       | storedValue
        'a hash shorter than accepted'                    | "\$scrypt\$ln=4,r=8,p=1\$$SALT_B64\$AA"
        'a truncated hash (scrypt hashes are prefixes)'   | "\$scrypt\$ln=4,r=8,p=1\$$SALT_B64\$${'A' * 20}"
        'a hash longer than any this plugin produces'     | "\$scrypt\$ln=4,r=8,p=1\$$SALT_B64\$${'A' * 4000}"
        'a salt longer than any this plugin produces'     | "\$scrypt\$ln=4,r=8,p=1\$${'A' * 4000}\$$HASH_B64"
        'a cost exponent of zero (scrypt requires N > 1)' | "\$scrypt\$ln=0,r=8,p=1\$$SALT_B64\$$HASH_B64"
        'a cost that would exhaust the heap'              | "\$scrypt\$ln=30,r=8,p=1\$$SALT_B64\$$HASH_B64"
        'a cost exponent just above the maximum'          | "\$scrypt\$ln=21,r=8,p=1\$$SALT_B64\$$HASH_B64"
        'a block size of zero'                            | "\$scrypt\$ln=4,r=0,p=1\$$SALT_B64\$$HASH_B64"
        'a block size just above the stored maximum'      | "\$scrypt\$ln=4,r=33,p=1\$$SALT_B64\$$HASH_B64"
        'a cost and block size whose product is a bomb'   | "\$scrypt\$ln=20,r=32,p=1\$$SALT_B64\$$HASH_B64"
        'a parallelization of zero'                       | "\$scrypt\$ln=4,r=8,p=0\$$SALT_B64\$$HASH_B64"
        'a parallelization just above the maximum'        | "\$scrypt\$ln=4,r=8,p=33\$$SALT_B64\$$HASH_B64"
        'a block size of 1 with a cost scrypt rejects'    | "\$scrypt\$ln=16,r=1,p=1\$$SALT_B64\$$HASH_B64"
    }

    /**
     * The reason is what the transformer logs when a stored value is rejected, which is the only way to tell
     * a hash that could not be verified from a wrong password. It must never repeat any part of the stored
     * value, so the untrusted fields (the algorithm, the parameter names, the salt and the hash) are only
     * ever named, not echoed.
     */
    @Unroll
    def "the decoder reports why a stored value is not a scrypt hash: #description"() {
        when:
        def result = ScryptPhcFormat.INSTANCE.decode(storedValue)

        then:
        result instanceof PhcDecodeResult.Invalid

        and:
        result.reason.contains(expectedReason)

        where:
        description                     | storedValue                                              || expectedReason
        'plaintext'                     | 's3cret'                                                 || 'not a PHC string'
        'another algorithm'             | "\$scrypt2\$ln=4,r=8,p=1\$$SALT_B64\$$HASH_B64"          || 'the algorithm is not scrypt'
        'a missing parameter'           | "\$scrypt\$ln=4,p=1\$$SALT_B64\$$HASH_B64"               || "the 'r' parameter is missing"
        'a duplicated parameter'        | "\$scrypt\$ln=4,ln=4,r=8\$$SALT_B64\$$HASH_B64"          || "the 'ln' parameter appears more than once"
        'a non-numeric parameter'       | "\$scrypt\$ln=lots,r=8,p=1\$$SALT_B64\$$HASH_B64"        || "the 'ln' parameter is not a number"
        'an unknown parameter'          | "\$scrypt\$ln=4,r=8,x=1\$$SALT_B64\$$HASH_B64"           || 'an unknown cost parameter'
        'a cost exponent out of range'  | "\$scrypt\$ln=0,r=8,p=1\$$SALT_B64\$$HASH_B64"           || 'ln=0 is outside the accepted 1..20'
        'a block size out of range'     | "\$scrypt\$ln=4,r=33,p=1\$$SALT_B64\$$HASH_B64"          || 'r=33 is outside the accepted 1..32'
        'a parallelization out of range'| "\$scrypt\$ln=4,r=8,p=33\$$SALT_B64\$$HASH_B64"          || 'p=33 is outside the accepted 1..32'
        'a cost scrypt does not define' | "\$scrypt\$ln=16,r=1,p=1\$$SALT_B64\$$HASH_B64"          || 'scrypt does not define a hash'
        'a memory bomb'                 | "\$scrypt\$ln=20,r=32,p=1\$$SALT_B64\$$HASH_B64"         || 'needs more than the 1073741824 bytes'
        'a salt that is not base64'     | "\$scrypt\$ln=4,r=8,p=1\$not base64!\$$HASH_B64"         || 'the salt is not valid base64'
        'a hash that is not base64'     | "\$scrypt\$ln=4,r=8,p=1\$$SALT_B64\$not base64!"         || 'the hash is not valid base64'
        'an empty salt'                 | "\$scrypt\$ln=4,r=8,p=1\$\$$HASH_B64"                    || 'the salt length 0 is outside'
        'a hash shorter than accepted'  | "\$scrypt\$ln=4,r=8,p=1\$$SALT_B64\$AA"                  || 'the hash length 1 is outside'
    }

    def "the reported reason repeats no part of the stored value"() {
        given: 'a stored value whose untrusted fields are all recognisable'
        def storedValue = '$scrypt$ln=4,unknownparameter=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo'

        when:
        def result = ScryptPhcFormat.INSTANCE.decode(storedValue)

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
        ScryptPhcFormat.INSTANCE.decode(storedValue) instanceof PhcDecodeResult.Decoded

        where:
        description                                | storedValue
        'the highest cost exponent'                | "\$scrypt\$ln=20,r=8,p=1\$$SALT_B64\$$HASH_B64"
        'the highest stored block size'            | "\$scrypt\$ln=18,r=32,p=1\$$SALT_B64\$$HASH_B64"
        'the highest parallelization'              | "\$scrypt\$ln=4,r=8,p=32\$$SALT_B64\$$HASH_B64"
        'the lowest cost exponent'                 | "\$scrypt\$ln=1,r=8,p=1\$$SALT_B64\$$HASH_B64"
        'a block size of 1 with the largest cost'  | "\$scrypt\$ln=15,r=1,p=1\$$SALT_B64\$$HASH_B64"
        'the shortest allowed salt'                | "\$scrypt\$ln=4,r=8,p=1\$AQ\$$HASH_B64"
        'the shortest allowed hash (16 bytes)'     | "\$scrypt\$ln=4,r=8,p=1\$$SALT_B64\$$SALT_B64"
    }

    /**
     * The schema's range constraints already bound every configuration leaf; this exercises the
     * belt-and-braces validation in ScryptHashingLimiter for configurations arriving another way.
     * The bounds are the generous stored-value ones, so the cheap parameters the rest of this spec
     * configures (below the schema's minimums) must stay usable.
     */
    @Unroll
    def "a configuration no stored value would be allowed to ask for is rejected: #description"() {
        when:
        new ScryptHashingLimiter(configuration(overrides))

        then:
        def ex = thrown(IllegalArgumentException)
        ex.message.contains(expectedInMessage)

        where:
        description                            | overrides                            | expectedInMessage
        'a cost exponent that would overflow'  | [costExponent: 31]                   | 'cost-exponent'
        'a cost exponent above the maximum'    | [costExponent: 21]                   | 'cost-exponent'
        'a cost exponent of zero'              | [costExponent: 0]                    | 'cost-exponent'
        'a block size above the stored max'    | [blockSize: 33]                      | 'block-size'
        'a block size of zero'                 | [blockSize: 0]                       | 'block-size'
        'block size 1 with a cost scrypt rejects' | [blockSize: 1, costExponent: 16]  | 'block-size 1'
        'a memory bomb within per-leaf bounds' | [costExponent: 20, blockSize: 32]    | 'memory'
        'a parallelization of zero'            | [parallelization: 0]                 | 'parallelization'
        'a parallelization above the maximum'  | [parallelization: 33]                | 'parallelization'
        'an empty salt'                        | [saltLength: 0]                      | 'salt-length'
        'a hash shorter than 16 bytes'         | [hashLength: 8]                      | 'hash-length'
        'no permits'                           | [maxConcurrentOperations: 0]         | 'max-concurrent-operations'
    }

    @Unroll
    def "a match with outdated parameters requests an upgrade: #description"() {
        given: 'a password transformed with the original settings'
        def transformed = scrypt().transform('user-1', "s3cret")

        and: 'a transformer with updated settings'
        def transformer = scrypt(overrides)

        expect:
        transformer.match('user-1', "s3cret", transformed) == new MatchResult.Match(true)

        where:
        description             | overrides
        'a higher cost'         | [costExponent: COST_EXPONENT + 1]
        'another block size'    | [blockSize: BLOCK_SIZE.intdiv(2)]
        'more parallelization'  | [parallelization: PARALLELIZATION + 1]
        'a longer salt'         | [saltLength: SALT_LENGTH * 2]
        'a longer hash'         | [hashLength: HASH_LENGTH * 2]
    }

    def "scrypt computes the same hash as a plain BouncyCastle computation"() {
        given:
        def transformer = scrypt()

        when: 'a password is transformed'
        def transformed = transformer.transform('user-1', "s3cret")
        def decoded = decode(transformed)

        and: 'the same hash is computed independently of the code under test'
        def expectedHash = SCrypt.generate("s3cret".getBytes(StandardCharsets.UTF_8),
                decoded.parameters.salt, 1 << COST_EXPONENT, BLOCK_SIZE, PARALLELIZATION, HASH_LENGTH)

        then:
        Arrays.equals(decoded.hash, expectedHash)
    }

    @Unroll
    def "a #description password read from a CharSequence is encoded like the same String"() {
        given:
        def transformer = scrypt()

        when: 'the password is transformed from a sequence that is not a String, which is then cleared'
        def sequence = new StringBuilder(password)
        def transformed = transformer.transform('user-1', sequence)
        sequence.length().times { sequence.setCharAt(it, ' ' as char) }

        and: 'the same hash is computed independently, from the password as a String'
        def decoded = decode(transformed)
        def expectedHash = SCrypt.generate(password.getBytes(StandardCharsets.UTF_8),
                decoded.parameters.salt, 1 << COST_EXPONENT, BLOCK_SIZE, PARALLELIZATION, HASH_LENGTH)

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

    /**
     * The test vectors of RFC 7914, section 12, wrapped in the PHC string format: only the container is
     * built here, the expected bytes are the RFC's.
     */
    @Unroll
    def "the RFC 7914 test vector with N=#n is accepted"() {
        given: 'the RFC vector as a stored PHC string'
        def stored = "\$scrypt\$ln=$ln,r=$r,p=$p\$${base64(salt.bytes)}\$${base64(expectedHex.decodeHex())}"

        and: 'a transformer configured just like the vector'
        def transformer = scrypt(
                costExponent: ln, blockSize: r, parallelization: p,
                saltLength: salt.length(), hashLength: 64)

        expect:
        transformer.match('user-1', password, stored) == new MatchResult.Match(false)

        and:
        transformer.match('user-1', "wrong", stored) == new MatchResult.NoMatch(false)

        where:
        n     | ln | r | p  | password        | salt             | expectedHex
        1024  | 10 | 8 | 16 | "password"      | "NaCl"           | 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640'
        16384 | 14 | 8 | 1  | "pleaseletmein" | "SodiumChloride" | '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'
    }

    private static ScryptHash decode(String encoded) {
        def result = ScryptPhcFormat.INSTANCE.decode(encoded)
        assert result instanceof PhcDecodeResult.Decoded: "not decoded: $result"
        return result.value
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().withoutPadding().encodeToString(bytes)
    }
}
