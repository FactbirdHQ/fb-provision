/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.model.GetEndpointRequest;
import com.aws.greengrass.model.GetEndpointResponse;
import com.aws.greengrass.model.GetEndpointResponseRejected;
import com.aws.greengrass.model.GetEndpointSubscriptionRequest;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttMessage;
import software.amazon.awssdk.crt.mqtt.QualityOfService;
import software.amazon.awssdk.iot.Timestamp;
import software.amazon.awssdk.iot.iotidentity.model.ErrorResponse;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * An AWS IoT service that assists in routing to the endpoint of the claimer
 * cloud.
 *
*/
public class GetEndpointClient {
    private MqttClientConnection connection = null;
    private final Gson gson = getGson();

    public GetEndpointClient(MqttClientConnection connection) {
        this.connection = connection;
    }

    private Gson getGson() {
        GsonBuilder gson = new GsonBuilder();
        gson.disableHtmlEscaping();
        gson.registerTypeAdapter(Timestamp.class, new Timestamp.Serializer());
        gson.registerTypeAdapter(Timestamp.class, new Timestamp.Deserializer());
        addTypeAdapters(gson);
        return gson.create();
    }

    private void addTypeAdapters(GsonBuilder gson) {
    }

    /**
     * Ask the Mgmt account for claim status. If device is claimed, the endpoint
     * of the corresponding cloud's iot data endpoint is returned.
     *
     * <p>If the device is offline, the PUBLISH packet will be sent once the
     * connection resumes.</p>
     *
     * @param request Message to be serialized and sent
     * @param qos Quality of Service for delivering this message
     * @return a future containing the MQTT packet id used to perform the
     *      publish operation
     *
     *      - For QoS 0, completes as soon as the packet is sent.
     *      - For QoS 1, completes when PUBACK is received.
     *      - QoS 2 is not supported by AWS IoT.
     */
    public CompletableFuture<Integer> publishGetEndpoint(
        String clientId,
        GetEndpointRequest request,
        QualityOfService qos) {
        String topic = String.format("endpoint/v1/%s", clientId);
        String payloadJson = gson.toJson(request);
        MqttMessage message = new MqttMessage(topic, payloadJson.getBytes(StandardCharsets.UTF_8), qos);
        return connection.publish(message);
    }

    /**
     * Subscribes to the accepted topic of the GetEndpoint operation.
     *
     * <p>Once subscribed, `handler` is invoked each time a message matching the
     * `topic` is received. It is possible for such messages to arrive before
     * the SUBACK is received.</p>
     *
     * @param request Subscription request configuration
     * @param qos Maximum requested QoS that server may use when sending
     *            messages to the client. The server may grant a lower QoS in
     *            the SUBACK
     * @param handler callback function to invoke with messages received on the
     *      subscription topic
     * @param exceptionHandler callback function to invoke if an exception
     *      occurred deserializing a message
     *
     * @return a future containing the MQTT packet id used to perform the
     *      subscribe operation
     */
    public CompletableFuture<Integer> subscribeToGetEndpointAccepted(
        String clientId,
        GetEndpointSubscriptionRequest request,
        QualityOfService qos,
        Consumer<GetEndpointResponse> handler,
        Consumer<Exception> exceptionHandler) {
        String topic = String.format("endpoint/v1/%s/accepted", clientId);
        Consumer<MqttMessage> messageHandler = (message) -> {
            try {
                String payload = new String(message.getPayload(), StandardCharsets.UTF_8);
                GetEndpointResponse response = gson.fromJson(payload, GetEndpointResponse.class);
                handler.accept(response);
            } catch (Exception e) {
                if (exceptionHandler != null) {
                    exceptionHandler.accept(e);
                }
            }
        };
        return connection.subscribe(topic, qos, messageHandler);
    }

    /**
     * Subscribes to the accepted topic of the GetEndpoint operation.
     *
     * <p>Once subscribed, `handler` is invoked each time a message matching the
     * `topic` is received. It is possible for such messages to arrive before
     * the SUBACK is received.</p>
     *
     * @param request Subscription request configuration
     * @param qos Maximum requested QoS that server may use when sending
     *            messages to the client. The server may grant a lower QoS in
     *            the SUBACK
     * @param handler callback function to invoke with messages received on the
     *      subscription topic
     *
     * @return a future containing the MQTT packet id used to perform the
     *      subscribe operation
     */
    public CompletableFuture<Integer> subscribeToGetEndpointAccepted(
        String clientId,
        GetEndpointSubscriptionRequest request,
        QualityOfService qos,
        Consumer<GetEndpointResponse> handler) {
        return subscribeToGetEndpointAccepted(clientId, request, qos, handler, null);
    }

    /**
     * Subscribes to the rejected topic of the GetEndpoint operation.
     *
     * <p>Once subscribed, `handler` is invoked each time a message matching the
     * `topic` is received. It is possible for such messages to arrive before
     * the SUBACK is received.</p>
     *
     * @param request Subscription request configuration
     * @param qos Maximum requested QoS that server may use when sending
     *            messages to the client. The server may grant a lower QoS in
     *            the SUBACK
     * @param handler callback function to invoke with messages received on the
     *      subscription topic
     * @param exceptionHandler callback function to invoke if an exception
     *      occurred deserializing a message
     *
     * @return a future containing the MQTT packet id used to perform the
     *      subscribe operation
     */
    public CompletableFuture<Integer> subscribeToGetEndpointRejected(
        String clientId,
        GetEndpointSubscriptionRequest request,
        QualityOfService qos,
        Consumer<GetEndpointResponseRejected> handler,
        Consumer<Exception> exceptionHandler) {
        String topic = String.format("endpoint/v1/%s/rejected", clientId);
        Consumer<MqttMessage> messageHandler = (message) -> {
            try {
                String payload = new String(message.getPayload(), StandardCharsets.UTF_8);
                GetEndpointResponseRejected response = gson.fromJson(payload, GetEndpointResponseRejected.class);
                handler.accept(response);
            } catch (Exception e) {
                if (exceptionHandler != null) {
                    exceptionHandler.accept(e);
                }
            }
        };
        return connection.subscribe(topic, qos, messageHandler);
    }

    /**
     * Subscribes to the rejected topic of the GetEndpoint operation.
     *
     * <p>Once subscribed, `handler` is invoked each time a message matching the
     * `topic` is received. It is possible for such messages to arrive before
     * the SUBACK is received.</p>
     *
     * @param request Subscription request configuration
     * @param qos Maximum requested QoS that server may use when sending
     *            messages to the client. The server may grant a lower QoS in
     *            the SUBACK
     * @param handler callback function to invoke with messages received on the
     *      subscription topic
     *
     * @return a future containing the MQTT packet id used to perform the
     *      subscribe operation
     */
    public CompletableFuture<Integer> subscribeToGetEndpointRejected(
        String clientId,
        GetEndpointSubscriptionRequest request,
        QualityOfService qos,
        Consumer<GetEndpointResponseRejected> handler) {
        return subscribeToGetEndpointRejected(clientId, request, qos, handler, null);
    }
}