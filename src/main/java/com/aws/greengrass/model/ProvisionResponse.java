/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.model;

/**
 * Success payload published by the fleet-management Router on
 * {@code provision/{uuid}/response}.
 */
public class ProvisionResponse {
    public String iotDataEndpoint;
    public String iotCredentialsEndpoint;
    public String provisioningToken;
}
