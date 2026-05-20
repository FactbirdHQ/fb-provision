/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.model;

/**
 * Payload published to {@code provision/{uuid}/request} when asking the
 * fleet-management Router to resolve this device's tenant endpoint and
 * mint a provisioning token.
 */
public class ProvisionRequest {
    public String uuid;
    public String signature;
}
