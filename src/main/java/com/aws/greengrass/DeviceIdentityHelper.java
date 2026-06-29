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
import java.io.InputStream;
import java.math.BigInteger;
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
    private final Logger logger = LogManager.getLogger(MqttConnectionHelper.class);

    String getClientId() {
        String result = null;
        String[] cmd = { "uuid" };
        try (InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();
                        Scanner s = new Scanner(inputStream).useDelimiter("\\A")) {
                result = s.hasNext() ? s.next().replaceAll(System.lineSeparator(), "") : null;
        } catch (IOException e) {
                e.printStackTrace();
        }
        return result;
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

            return new BigInteger(1, signature).toString(16);
    }
}
