/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;

import java.util.concurrent.TimeUnit;

/**
 * Unbounded retry with exponential backoff for boot-time provisioning stages.
 *
 * <p>Provisioning runs once per Greengrass process start. If a stage gives up,
 * the device runs unprovisioned until the next restart, because the nucleus
 * only re-invokes the plugin 3 times, seconds apart, and only for
 * {@code RetryableProvisioningException}. Network readiness at boot can lag by
 * minutes (or longer), so the plugin must carry its own durable retry.</p>
 *
 * <p>Every attempt failure is retried, forever, with the delay doubling from
 * {@link #INITIAL_DELAY_SECONDS} up to {@link #MAX_DELAY_SECONDS}. The only way
 * out is success or {@link InterruptedException} (nucleus shutdown), which is
 * propagated immediately without sleeping.</p>
 */
final class RetryBackoff {

    static final long INITIAL_DELAY_SECONDS = 20;
    static final long MAX_DELAY_SECONDS = 300;

    private static final Logger logger = LogManager.getLogger(RetryBackoff.class);

    /** Sleep abstraction so tests can run without wall-clock delays. */
    @FunctionalInterface
    interface Sleeper {
        void sleep(long seconds) throws InterruptedException;
    }

    /** One attempt of a retried stage. */
    @FunctionalInterface
    interface Attempt<T> {
        T run() throws Exception;
    }

    private final Sleeper sleeper;

    RetryBackoff() {
        this(TimeUnit.SECONDS::sleep);
    }

    RetryBackoff(Sleeper sleeper) {
        this.sleeper = sleeper;
    }

    /**
     * Run {@code attempt} until it returns, sleeping with exponential backoff
     * between failures.
     *
     * @param stage   human-readable stage name for the log
     * @param attempt the work to retry
     * @param <T>     result type
     * @return the first successful result
     * @throws InterruptedException if the thread is interrupted, either inside
     *                              the attempt or while sleeping
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    <T> T runForever(String stage, Attempt<T> attempt) throws InterruptedException {
        long delaySeconds = INITIAL_DELAY_SECONDS;
        int attemptNumber = 0;
        while (true) {
            attemptNumber++;
            try {
                T result = attempt.run();
                if (attemptNumber > 1) {
                    logger.atInfo().kv("stage", stage).kv("attempt", attemptNumber)
                            .log("Stage succeeded after retry");
                }
                return result;
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                logger.atWarn().setCause(e)
                        .kv("stage", stage)
                        .kv("attempt", attemptNumber)
                        .kv("nextDelaySeconds", delaySeconds)
                        .log("Stage failed, retrying");
                sleeper.sleep(delaySeconds);
                delaySeconds = Math.min(delaySeconds * 2, MAX_DELAY_SECONDS);
            }
        }
    }
}
