/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
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
    /**
     * Tenant fleet-provisioning template to call {@code RegisterThing} with.
     * Absent ({@code null}) from a Router that predates it; the plugin then
     * falls back to its {@code provisioningTemplate} parameter.
     */
    public String provisioningTemplate;
}
