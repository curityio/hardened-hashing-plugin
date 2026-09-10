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

import spock.lang.Specification
import spock.lang.Unroll

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The limiter is what bounds how much heap Argon2 hashing can use, so what matters is that it never lets more
 * operations run at once than it was configured for.
 */
class Argon2HashingLimiterSpec extends Specification
{
    @Unroll
    def "no more than #maxConcurrent operations run at the same time"()
    {
        given:
        def limiter = new Argon2HashingLimiter(configurationAllowing(maxConcurrent))
        def running = new AtomicInteger()
        def peak = new AtomicInteger()
        def started = new CountDownLatch(threads)
        def executor = Executors.newFixedThreadPool(threads)

        when: 'many more threads than permits all try to hash at once'
        def futures = (1..threads).collect {
            executor.submit({
                limiter.hashing {
                    peak.accumulateAndGet(running.incrementAndGet(), Math::max)
                    // hold the permit long enough that every other thread has a chance to pile up
                    Thread.sleep(20)
                    running.decrementAndGet()
                    started.countDown()
                    return null
                }
            } as Runnable)
        }
        futures*.get(30, TimeUnit.SECONDS)

        then: 'the permit count was never exceeded'
        peak.get() <= maxConcurrent

        and: 'and every operation did run'
        started.await(0, TimeUnit.SECONDS)

        cleanup:
        executor.shutdownNow()

        where:
        maxConcurrent | threads
        1             | 8
        2             | 8
        4             | 16
    }

    def "a permit is released when the operation throws"()
    {
        given: 'a limiter that allows a single operation at a time'
        def limiter = new Argon2HashingLimiter(configurationAllowing(1))

        when: 'an operation fails'
        limiter.hashing { throw new IllegalStateException("boom") }

        then:
        thrown IllegalStateException

        and: 'the permit is back, so the limiter is still usable'
        limiter.hashing { "hashed" } == "hashed"
    }

    def "the value returned by the operation is passed through"()
    {
        given:
        def limiter = new Argon2HashingLimiter(configurationAllowing(2))

        expect:
        limiter.hashing { [1, 2, 3] as byte[] } == [1, 2, 3] as byte[]
    }

    private static Argon2Configuration configurationAllowing(int maxConcurrentOperations)
    {
        return new Argon2Configuration() {
            String id() { "argon2" }

            int getMemoryCost() { 256 }

            int getIterations() { 1 }

            int getParallelism() { 1 }

            int getSaltLength() { 16 }

            int getHashLength() { 32 }

            int getMaxConcurrentOperations() { maxConcurrentOperations }
        }
    }
}
