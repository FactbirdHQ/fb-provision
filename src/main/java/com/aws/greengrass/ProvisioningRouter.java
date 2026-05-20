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

    /**
     * Router error message fragment indicating the device hasn't been
     * claimed yet — matches the `RouterError::NotClaimed` Display impl in
     * the cloud handler (`nest-2/.../router.rs`). Matched as a substring
     * because the Router serialises errors as a free-form
     * {@code anyhow::Error} chain string.
     */
    private static final String NOT_CLAIMED_FRAGMENT = "not claimed";

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
     * success payload on {@code provision/{uuid}/response}.</p>
     *
     * <p>Router <em>error</em> payloads are handled differently
     * depending on whether waiting longer could plausibly help:</p>
     * <ul>
     *   <li>{@code "device not claimed"} — the subscription is left
     *       open and the future stays incomplete. claim_reactor pushes
     *       a success payload to the same topic when the DynamoDB
     *       claim transition fires. The caller's outer wall-clock
     *       timeout (~15 min) is the safety net for a missed push.</li>
     *   <li>Anything else (decommissioned, signature verification
     *       failed, …) — the future is completed exceptionally so the
     *       caller can tear down and retry, since the same error will
     *       just repeat on the same subscription.</li>
     * </ul>
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
                    String msg = errorResponse.error == null ? "" : errorResponse.error;
                    if (msg.contains(NOT_CLAIMED_FRAGMENT)) {
                        // claim_reactor will push a success payload to the
                        // same topic when the DynamoDB claim transition
                        // fires. Stay subscribed; the caller's wall-clock
                        // timeout is the safety net for a missed push.
                        logger.atInfo().log(
                                "Router responded: {}. Subscription stays open; "
                                        + "claim_reactor will push when claim status flips.",
                                msg);
                    } else {
                        // Other Router errors (decommissioned, bad signature,
                        // …) won't resolve by waiting on the same
                        // subscription. Surface so the outer loop tears it
                        // down and tries again from scratch.
                        logger.atWarn().log(
                                "Router rejected provisioning: {}. Reconnecting and retrying.",
                                msg);
                        future.completeExceptionally(new RetryableProvisioningException(
                                "Router rejected provisioning: " + msg));
                    }
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
