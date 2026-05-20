/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.model;

/**
 * Failure payload published by the fleet-management Router on
 * {@code provision/{uuid}/response} (same topic as the success payload —
 * the consumer disambiguates by deserialisation).
 */
public class ProvisionError {
    public String error;
}
