/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.model;

/**
 * Failure payload published by the fleet-management Router on
 * {@code provision/{uuid}/response} (same topic as the success payload —
 * the consumer disambiguates by inspecting payload shape).
 *
 * Mirrors {@code fleet_provisioning_types::mqtt::provision::ProvisionError}
 * on the cloud side. {@link #code} is the structured discriminator;
 * {@link #message} is a human-readable detail suitable for logging but
 * not for behaviour switching.
 */
public class ProvisionError {
    /** See {@link ProvisionErrorCode}. */
    public ProvisionErrorCode code;
    public String message;
}
