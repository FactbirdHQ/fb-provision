/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.model.ProvisionRequest;
import com.aws.greengrass.model.ProvisionResponse;
import com.aws.greengrass.provisioning.exceptions.RetryableProvisioningException;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.QualityOfService;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import static com.aws.greengrass.FutureExceptionHandler.AWS_IOT_DEFAULT_TIMEOUT_SECONDS;

/**
 * Drives the fleet-management Router round-trip: subscribes to
 * {@code provision/{uuid}/response}, publishes {@code provision/{uuid}/request}
 * with {@code {uuid, signature}}, and returns the {@link ProvisionResponse}
 * (iotDataEndpoint + iotCredentialsEndpoint + provisioningToken).
 *
 * Replaces the legacy {@code MgmtCloudRouter} that round-tripped on
 * {@code endpoint/v1/{uuid}} against mgmt-services.
 */
public class ProvisioningRouter {

    private static final Logger logger = LogManager.getLogger(ProvisioningRouter.class);

    private final ProvisioningRouterClient client;

    public ProvisioningRouter(MqttClientConnection connection) {
        this.client = new ProvisioningRouterClient(connection);
    }

    // For unit testing
    ProvisioningRouter(ProvisioningRouterClient client) {
        this.client = client;
    }

    /**
     * Ask the fleet-management Router to resolve this device's tenant
     * endpoint and mint a provisioning token.
     *
     * <p>The returned future completes when the Router (or its
     * claim_reactor counterpart on a DynamoDB stream event) publishes a
     * success payload on {@code provision/{uuid}/response}. Router
     * <em>error</em> payloads (e.g. "device not claimed") are logged and
     * <strong>do not</strong> complete the future: the subscription stays
     * open so the device receives the eventual success message pushed by
     * claim_reactor when claim status flips. The caller is expected to
     * apply an outer wall-clock timeout (~15 min) as a safety net in case
     * the message is missed or the subscription failed silently.</p>
     */
    public Future<ProvisionResponse> route(String uuid, String signature)
            throws InterruptedException, RetryableProvisioningException {
        return route(uuid, signature, AWS_IOT_DEFAULT_TIMEOUT_SECONDS);
    }

    /**
     * Same as {@link #route(String, String)} but with an overridable
     * subscription-ack timeout.
     *
     * @param timeout subscription-ack timeout in seconds (applied to the
     *                MQTT SUBACK / PUBACK only; the future itself never
     *                times out from here — the caller owns the wall clock).
     */
    public Future<ProvisionResponse> route(String uuid, String signature, int timeout)
            throws InterruptedException, RetryableProvisioningException {

        CompletableFuture<ProvisionResponse> future = new CompletableFuture<>();

        CompletableFuture<Integer> subscribed = client.subscribeToProvisionResponse(
                uuid,
                QualityOfService.AT_LEAST_ONCE,
                future::complete,
                (errorResponse) -> {
                    // Intentionally do NOT complete the future. The Router
                    // returns "not claimed" / similar transient errors when
                    // the device hasn't been claimed yet; claim_reactor will
                    // push a success payload to the same topic when the
                    // DynamoDB claim transition happens, and that completes
                    // the future. The caller's outer ~15-min wall-clock
                    // timeout is the safety net for missed messages.
                    logger.atInfo().log(
                            "Router responded with error: {}. Subscription stays open; "
                                    + "claim_reactor will push when claim status flips.",
                            errorResponse.error);
                },
                (e) -> {
                    // Protocol-level deserialisation failure is a real bug
                    // (router and device disagree on the wire format). Surface
                    // it so the outer loop can drop and re-establish.
                    logger.atError().setCause(e).log("Failed to parse provision response payload");
                    future.completeExceptionally(e);
                });
        FutureExceptionHandler.getFutureAfterCompletion(subscribed, timeout);

        logger.atInfo().log("Subscribed to provision/{}/response", uuid);

        ProvisionRequest request = new ProvisionRequest();
        request.uuid = uuid;
        request.signature = signature;

        CompletableFuture<Integer> published = client.publishProvisionRequest(
                uuid,
                request,
                QualityOfService.AT_LEAST_ONCE);
        FutureExceptionHandler.getFutureAfterCompletion(published);

        logger.atInfo().log("Published to provision/{}/request", uuid);
        return future;
    }
}
