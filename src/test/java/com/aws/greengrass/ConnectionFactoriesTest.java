/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;

import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Provisioning is retried with a fresh MQTT connection per attempt, so the
 * helpers handed out by the factories must be bound to the connection passed
 * in, not to whichever connection the factory saw first.
 */
@ExtendWith(MockitoExtension.class)
public class ConnectionFactoriesTest {

    @Mock
    private MqttClientConnection first;
    @Mock
    private MqttClientConnection second;

    @Test
    public void GIVEN_two_connections_WHEN_router_requested_for_second_THEN_it_uses_second() throws Exception {
        when(second.subscribe(anyString(), any(), any())).thenReturn(CompletableFuture.completedFuture(1));
        when(second.publish(any())).thenReturn(CompletableFuture.completedFuture(1));
        ProvisioningRouterFactory factory = new ProvisioningRouterFactory();

        factory.getInstance(first);
        factory.getInstance(second).route("uuid");

        verify(second).publish(any());
        verify(first, never()).subscribe(anyString(), any(), any());
        verify(first, never()).publish(any());
    }

    @Test
    public void GIVEN_two_connections_WHEN_identity_helper_requested_for_second_THEN_it_uses_second() throws Exception {
        when(second.subscribe(anyString(), any(), any())).thenReturn(CompletableFuture.completedFuture(1));
        // The SDK's IotIdentityClient uses the (message, qos, retain) publish overload.
        when(second.publish(any(), any(), anyBoolean())).thenReturn(CompletableFuture.completedFuture(1));
        IotIdentityHelperFactory factory = new IotIdentityHelperFactory();

        factory.getInstance(first);
        factory.getInstance(second).createKeysAndCertificate();

        verify(second).publish(any(), any(), anyBoolean());
        verify(first, never()).subscribe(anyString(), any(), any());
        verify(first, never()).publish(any(), any(), anyBoolean());
    }
}
