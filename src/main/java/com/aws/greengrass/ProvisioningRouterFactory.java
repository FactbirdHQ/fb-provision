/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import software.amazon.awssdk.crt.mqtt.MqttClientConnection;

public class ProvisioningRouterFactory {

    /**
     * Provides a {@link ProvisioningRouter} bound to the given connection.
     *
     * <p>Not cached: provisioning is retried with a fresh MQTT connection per
     * attempt, and a ProvisioningRouter holds the connection it was created with.
     * Caching the first instance made every retry operate on a closed connection
     * ("Invalid connection during subscribe").</p>
     */
    public ProvisioningRouter getInstance(MqttClientConnection connection) {
        return new ProvisioningRouter(connection);
    }
}
