/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Modifications Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith({ GGExtension.class })
class DeviceIdentityHelperTest {

    private final DeviceIdentityHelper helper = new DeviceIdentityHelper();

    private String[] stubUuid(Path dir, String body) throws IOException {
        Path script = dir.resolve("uuid-stub.sh");
        Files.write(script, ("#!/bin/sh\n" + body + "\n").getBytes(StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(script,
                Stream.of("OWNER_READ", "OWNER_WRITE", "OWNER_EXECUTE")
                        .map(java.nio.file.attribute.PosixFilePermission::valueOf)
                        .collect(Collectors.toCollection(java.util.LinkedHashSet::new)));
        return new String[] { script.toString() };
    }

    @Test
    void GIVEN_uuid_prints_identity_WHEN_getClientId_THEN_returns_it(@TempDir Path dir) throws IOException {
        String[] cmd = stubUuid(dir, "echo cb7bc3095fc54c7c83bfbb0e4414afe2");
        assertEquals("cb7bc3095fc54c7c83bfbb0e4414afe2", helper.getClientId(cmd));
    }

    @Test
    void GIVEN_uuid_exits_nonzero_WHEN_getClientId_THEN_throws_with_stderr(@TempDir Path dir) throws IOException {
        // Mirrors the container shim's behaviour when /data/.device-uuid is absent.
        String[] cmd = stubUuid(dir, "echo 'uuid: /data/.device-uuid missing' >&2; exit 1");

        DeviceProvisioningRuntimeException ex = assertThrows(DeviceProvisioningRuntimeException.class,
                () -> helper.getClientId(cmd));

        assertTrue(ex.getMessage().contains("exited 1"), ex.getMessage());
        // The command's own diagnosis must survive — discarding it is what made the
        // original failure surface as an opaque NullPointerException in sign().
        assertTrue(ex.getMessage().contains("/data/.device-uuid missing"), ex.getMessage());
    }

    @Test
    void GIVEN_uuid_prints_nothing_WHEN_getClientId_THEN_throws(@TempDir Path dir) throws IOException {
        String[] cmd = stubUuid(dir, "exit 0");

        DeviceProvisioningRuntimeException ex = assertThrows(DeviceProvisioningRuntimeException.class,
                () -> helper.getClientId(cmd));

        assertTrue(ex.getMessage().contains("printed nothing"), ex.getMessage());
    }

    @Test
    void GIVEN_uuid_not_on_path_WHEN_getClientId_THEN_throws(@TempDir Path dir) {
        String[] cmd = { dir.resolve("does-not-exist").toString() };

        DeviceProvisioningRuntimeException ex = assertThrows(DeviceProvisioningRuntimeException.class,
                () -> helper.getClientId(cmd));

        assertTrue(ex.getMessage().contains("PATH"), ex.getMessage());
    }

    @Test
    void GIVEN_uuid_output_has_trailing_newline_WHEN_getClientId_THEN_trimmed(@TempDir Path dir) throws IOException {
        String[] cmd = stubUuid(dir, "printf 'abc123\\n'");
        assertEquals("abc123", helper.getClientId(cmd));
    }
}
