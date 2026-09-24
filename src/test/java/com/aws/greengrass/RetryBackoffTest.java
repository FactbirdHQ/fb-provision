/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RetryBackoffTest {

    private final List<Long> sleeps = new ArrayList<>();
    private final RetryBackoff backoff = new RetryBackoff(sleeps::add);

    @Test
    public void GIVEN_attempt_succeeds_first_time_WHEN_run_THEN_no_sleep() throws InterruptedException {
        String result = backoff.runForever("stage", () -> "ok");
        assertEquals("ok", result);
        assertTrue(sleeps.isEmpty());
    }

    @Test
    public void GIVEN_attempt_fails_repeatedly_WHEN_run_THEN_delay_doubles_to_cap() throws InterruptedException {
        AtomicInteger calls = new AtomicInteger();
        String result = backoff.runForever("stage", () -> {
            if (calls.incrementAndGet() <= 7) {
                throw new RuntimeException("dns");
            }
            return "ok";
        });
        assertEquals("ok", result);
        assertEquals(8, calls.get());
        assertEquals(Arrays.asList(20L, 40L, 80L, 160L, 300L, 300L, 300L), sleeps);
    }

    @Test
    public void GIVEN_attempt_throws_interrupted_WHEN_run_THEN_propagates_without_sleep() {
        assertThrows(InterruptedException.class, () -> backoff.runForever("stage", () -> {
            throw new InterruptedException("shutdown");
        }));
        assertTrue(sleeps.isEmpty());
    }

    @Test
    public void GIVEN_sleeper_interrupted_WHEN_run_THEN_propagates() {
        RetryBackoff interrupting = new RetryBackoff(seconds -> {
            throw new InterruptedException("shutdown");
        });
        AtomicInteger calls = new AtomicInteger();
        assertThrows(InterruptedException.class, () -> interrupting.runForever("stage", () -> {
            calls.incrementAndGet();
            throw new RuntimeException("dns");
        }));
        assertEquals(1, calls.get());
    }
}
