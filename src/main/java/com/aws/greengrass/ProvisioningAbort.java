/*
 * Copyright 2022-2026 Factbird ApS. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

/**
 * Ends the unbounded provisioning retry: the attempt failed in a way no later
 * attempt can recover from with the inputs it has. {@link RetryBackoff} rethrows
 * it instead of sleeping, so it reaches the nucleus and fails this provisioning
 * run. Used for a direct-mode provisioning token that the tenant authorizer has
 * already consumed.
 */
public class ProvisioningAbort extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ProvisioningAbort(String message, Throwable cause) {
        super(message, cause);
    }
}
