/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import software.amazon.awssdk.crt.mqtt.MqttClientConnection;

public class IotIdentityHelperFactory {

    /**
     * Provides a {@link IotIdentityHelper} bound to the given connection.
     *
     * <p>Not cached: provisioning is retried with a fresh MQTT connection per
     * attempt, and a IotIdentityHelper holds the connection it was created with. Caching
     * the first instance made every retry operate on a closed connection
     * ("Invalid connection during subscribe").</p>
     *
     * @param connection Mqtt client connection to AWS IoT
     * @return {@link IotIdentityHelper}
     */
    public IotIdentityHelper getInstance(MqttClientConnection connection) {
        return new IotIdentityHelper(connection);
    }
}
