/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.model;

import com.google.gson.annotations.SerializedName;

/**
 * Discriminator for {@link ProvisionError}. Mirrors
 * {@code fleet_provisioning_types::mqtt::provision::ProvisionErrorCode}
 * on the cloud side; values must stay in sync.
 *
 * <ul>
 *   <li>{@link #NOT_CLAIMED} — the device hasn't been claimed yet.
 *       Keep the {@code provision/{uuid}/response} subscription open
 *       and wait for {@code claim_reactor} to push a success payload
 *       when the DynamoDB claim transition fires.</li>
 *   <li>{@link #DECOMMISSIONED} — terminal. Fails the attempt; the
 *       plugin's outer retry backs off and starts over. Operator
 *       intervention is typically required.</li>
 *   <li>{@link #INTERNAL} — catch-all server failure; fails the
 *       attempt, retried with backoff.</li>
 *   <li>{@link #UNKNOWN} — forward-compat catch-all for codes the
 *       client doesn't know about. Treat as {@link #INTERNAL}.</li>
 * </ul>
 */
public enum ProvisionErrorCode {
    @SerializedName("notClaimed")
    NOT_CLAIMED,
    @SerializedName("decommissioned")
    DECOMMISSIONED,
    @SerializedName("internal")
    INTERNAL,
    /** Fallback. Gson maps unknown values to {@code null}; the
     * deserialiser substitutes this. */
    UNKNOWN
}
