/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.model.ProvisionError;
import com.aws.greengrass.model.ProvisionRequest;
import com.aws.greengrass.model.ProvisionResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttMessage;
import software.amazon.awssdk.crt.mqtt.QualityOfService;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Talks to the fleet-management Router over the
 * {@code provision/{uuid}/request} and {@code provision/{uuid}/response}
 * MQTT topics. Replaces the legacy {@code endpoint/v1/{uuid}} mgmt-services
 * round-trip.
 */
public class ProvisioningRouterClient {
    private final MqttClientConnection connection;
    private final Gson gson;

    public ProvisioningRouterClient(MqttClientConnection connection) {
        this.connection = connection;
        GsonBuilder builder = new GsonBuilder();
        builder.disableHtmlEscaping();
        this.gson = builder.create();
    }

    /**
     * Publish a {@link ProvisionRequest} to {@code provision/{uuid}/request}.
     */
    public CompletableFuture<Integer> publishProvisionRequest(
            String clientId,
            ProvisionRequest request,
            QualityOfService qos) {
        String topic = String.format("provision/%s/request", clientId);
        String payloadJson = gson.toJson(request);
        MqttMessage message = new MqttMessage(topic, payloadJson.getBytes(StandardCharsets.UTF_8), qos);
        return connection.publish(message);
    }

    /**
     * Subscribe to {@code provision/{uuid}/response}. The Router multiplexes
     * success and error payloads on this single topic; the message handler
     * tries {@link ProvisionResponse} first, falls back to
     * {@link ProvisionError}, and invokes the matching consumer.
     */
    public CompletableFuture<Integer> subscribeToProvisionResponse(
            String clientId,
            QualityOfService qos,
            Consumer<ProvisionResponse> onResponse,
            Consumer<ProvisionError> onError,
            Consumer<Exception> onException) {
        String topic = String.format("provision/%s/response", clientId);
        Consumer<MqttMessage> messageHandler = (message) -> {
            try {
                String payload = new String(message.getPayload(), StandardCharsets.UTF_8);
                JsonObject json = JsonParser.parseString(payload).getAsJsonObject();
                if (json.has("iotDataEndpoint") || json.has("provisioningToken")) {
                    onResponse.accept(gson.fromJson(json, ProvisionResponse.class));
                } else if (json.has("error")) {
                    onError.accept(gson.fromJson(json, ProvisionError.class));
                } else {
                    throw new IllegalArgumentException(
                            "provision response payload matched neither success nor error shape: " + payload);
                }
            } catch (Exception e) {
                if (onException != null) {
                    onException.accept(e);
                }
            }
        };
        return connection.subscribe(topic, qos, messageHandler);
    }
}
