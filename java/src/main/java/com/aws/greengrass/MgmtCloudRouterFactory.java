/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import software.amazon.awssdk.crt.mqtt.MqttClientConnection;

public class MgmtCloudRouterFactory {
    MgmtCloudRouter mgmtCloudRouter;

    /**
     * Provides a singleton instance of {@link MgmtCloudRouter}.
     * 
     * @param connection Mqtt client connection to AWS IoT
     * @return {@link MgmtCloudRouter}
     */
    public MgmtCloudRouter getInstance(MqttClientConnection connection) {
        if (mgmtCloudRouter == null) {
            mgmtCloudRouter = new MgmtCloudRouter(connection);
        }
        return mgmtCloudRouter;
    }
}