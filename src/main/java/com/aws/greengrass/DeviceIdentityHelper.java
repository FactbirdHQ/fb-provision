/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Modifications Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.aws.greengrass;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class DeviceIdentityHelper {
    private final Logger logger = LogManager.getLogger(DeviceIdentityHelper.class);

    /**
     * Resolve the device UUID by running `uuid` on PATH. Each platform supplies its
     * own: the Yocto image installs it via the fb-uuid recipe, the factory container
     * ships a shim that reads /data/.device-uuid. The indirection is deliberate —
     * the plugin must not know any platform's on-disk layout.
     *
     * <p>Failures are fatal and must say so. This previously returned null on any
     * error, which surfaced downstream as an opaque NullPointerException in sign()
     * while the command's own diagnosis was discarded with its stderr.
     *
     * @return the device UUID, never null or empty
     * @throws DeviceProvisioningRuntimeException if `uuid` is missing, exits non-zero,
     *         or prints nothing
     */
    String getClientId() {
        return getClientId(new String[] { "uuid" });
    }

    // Visible for testing: lets a test point at a stub instead of relying on PATH.
    String getClientId(String[] cmd) {
        try {
                Process process = Runtime.getRuntime().exec(cmd);

                String stdout;
                String stderr;
                try (Scanner out = new Scanner(process.getInputStream()).useDelimiter("\\A");
                                Scanner err = new Scanner(process.getErrorStream()).useDelimiter("\\A")) {
                        stdout = out.hasNext() ? out.next().trim() : "";
                        stderr = err.hasNext() ? err.next().trim() : "";
                }

                int exitCode = process.waitFor();
                if (exitCode != 0) {
                        throw new DeviceProvisioningRuntimeException(
                                        "`uuid` exited " + exitCode + ", cannot determine device identity"
                                                        + (stderr.isEmpty() ? "" : ": " + stderr));
                }
                if (stdout.isEmpty()) {
                        throw new DeviceProvisioningRuntimeException(
                                        "`uuid` printed nothing, cannot determine device identity");
                }

                logger.atDebug().kv("uuid", stdout).log("Resolved device identity");
                return stdout;
        } catch (IOException e) {
                throw new DeviceProvisioningRuntimeException(
                                "Failed to run `uuid` — is it on PATH?", e);
        } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new DeviceProvisioningRuntimeException("Interrupted while running `uuid`", e);
        }
    }

    PrivateKey readPrivateKey(File file) throws GeneralSecurityException, IOException {
            String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

            String privateKeyPEM = key
                            .replace("-----BEGIN PRIVATE KEY-----", "")
                            .replaceAll(System.lineSeparator(), "")
                            .replace("-----END PRIVATE KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return (PrivateKey) keyFactory.generatePrivate(keySpec);
    }

    String sign(String plainText, PrivateKey privateKey) throws GeneralSecurityException, IOException {
            Signature privateSignature = Signature.getInstance("SHA256withECDSAinP1363format");
            privateSignature.initSign(privateKey);
            privateSignature.update(plainText.getBytes("UTF-8"));

            byte[] signature = privateSignature.sign();

            // Encode the raw P1363 (r||s) signature as fixed-width hex.
            // BigInteger(1, ...).toString(16) drops leading zero bytes, yielding
            // an odd-length/short string the fleet authorizer rejects with
            // "ATECC signature not valid hex".
            StringBuilder hex = new StringBuilder(signature.length * 2);
            for (byte b : signature) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            return hex.toString();
    }
}
