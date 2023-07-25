/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.model.GetEndpointRequest;
import com.aws.greengrass.model.GetEndpointResponse;
import com.aws.greengrass.model.GetEndpointSubscriptionRequest;
import com.aws.greengrass.provisioning.exceptions.RetryableProvisioningException;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.QualityOfService;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import static com.aws.greengrass.FutureExceptionHandler.AWS_IOT_DEFAULT_TIMEOUT_SECONDS;

public class MgmtCloudRouter {

    private static final Logger logger = LogManager.getLogger(MgmtCloudRouter.class);

    private final GetEndpointClient getEndpointClient;

    public MgmtCloudRouter(MqttClientConnection connection) {
        this.getEndpointClient = new GetEndpointClient(connection);
    }

    // For unit testing
    MgmtCloudRouter(GetEndpointClient getEndpointClient) {
        this.getEndpointClient = getEndpointClient;
    }

    /**
     * Creates Keys and certificate in AWS Iot and returns them back.
     * 
     * @return {@link GetEndpointResponse}
     * @throws InterruptedException           on thread interruption
     * @throws RetryableProvisioningException on transient errors like timeout
     */
    public Future<GetEndpointResponse> getEndpoint(String uuid, String signature) throws InterruptedException,
            RetryableProvisioningException {
        return getEndpoint(uuid, signature, AWS_IOT_DEFAULT_TIMEOUT_SECONDS);
    }

    /**
     * Creates Keys and certificate in AWS Iot and returns them back.
     * 
     * @param timeout iot connection timeout
     * @return {@link GetEndpointResponse}
     * @throws InterruptedException           on thread interruption
     * @throws RetryableProvisioningException on transient errors like timeout
     */
    public Future<GetEndpointResponse> getEndpoint(String uuid, String signature, int timeout) 
        throws InterruptedException, RetryableProvisioningException {

        CompletableFuture<GetEndpointResponse> getEndpointFuture = new CompletableFuture<>();
        GetEndpointSubscriptionRequest getEndpointSubscriptionRequest = new GetEndpointSubscriptionRequest();

        CompletableFuture<Integer> getEndpointSubscribedAccepted = getEndpointClient
                .subscribeToGetEndpointAccepted(
                        uuid,
                        getEndpointSubscriptionRequest,
                        QualityOfService.AT_LEAST_ONCE,
                        (response) -> getEndpointFuture.complete(response));
        FutureExceptionHandler.getFutureAfterCompletion(getEndpointSubscribedAccepted, timeout);

        logger.atInfo().log("Subscribed to GetEndpointAccepted");

        CompletableFuture<Integer> getEndpointSubscribedRejected = getEndpointClient.subscribeToGetEndpointRejected(
                uuid,
                getEndpointSubscriptionRequest,
                QualityOfService.AT_LEAST_ONCE,
                (errorResponse) -> {
                    RuntimeException e = new RuntimeException(errorResponse.errorMessage);
                    getEndpointFuture.completeExceptionally(e);
                });
        FutureExceptionHandler.getFutureAfterCompletion(getEndpointSubscribedRejected, timeout);

        logger.atInfo().log("Subscribed to GetEndpointRejected");

        GetEndpointRequest getEndpointRequest = new GetEndpointRequest();
        getEndpointRequest.uuid = uuid;
        getEndpointRequest.signature = signature;

        CompletableFuture<Integer> publishGetEndpoint = getEndpointClient.publishGetEndpoint(
                uuid,
                getEndpointRequest,
                QualityOfService.AT_LEAST_ONCE);
        FutureExceptionHandler.getFutureAfterCompletion(publishGetEndpoint);

        logger.atInfo().log("Published to GetEndpoint");
        return getEndpointFuture;
    }
}
