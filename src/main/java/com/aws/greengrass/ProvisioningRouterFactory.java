/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import software.amazon.awssdk.crt.mqtt.MqttClientConnection;

public class ProvisioningRouterFactory {
    private ProvisioningRouter provisioningRouter;

    /**
     * Provides a singleton instance of {@link ProvisioningRouter}.
     */
    public ProvisioningRouter getInstance(MqttClientConnection connection) {
        if (provisioningRouter == null) {
            provisioningRouter = new ProvisioningRouter(connection);
        }
        return provisioningRouter;
    }
}
