/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.model.GetEndpointResponse;
import com.aws.greengrass.provisioning.ProvisionConfiguration;
import com.aws.greengrass.provisioning.ProvisionContext;
import com.aws.greengrass.provisioning.exceptions.RetryableProvisioningException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.crt.CrtRuntimeException;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttException;
import software.amazon.awssdk.iot.iotidentity.model.CreateCertificateFromCsrResponse;
import software.amazon.awssdk.iot.iotidentity.model.CreateKeysAndCertificateResponse;
import software.amazon.awssdk.iot.iotidentity.model.RegisterThingResponse;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import static com.aws.greengrass.FleetProvisioningByClaimPlugin.AWS_REGION_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.CLAIM_CERTIFICATE_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PRIVATE_KEY_PATH_RELATIVE_TO_ROOT;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PROVISION_ENDPOINT_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PROVISIONING_TEMPLATE_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PROXY_URL_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.ROOT_CA_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.ROOT_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.TEMPLATE_PARAMETERS_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.IOT_ROLE_ALIAS_PARAMETER_NAME;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionUltimateCauseOfType;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionUltimateCauseWithMessage;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class FleetProvisioningByClaimPluginTest {

    private static final String MOCK_PROV_TEMPLATE_NAME = "MOCK_PROV_TEMPLATE_NAME";
    private static final String DEFAULT_PROVISIONING_POLICY = "PROVISION_IF_NOT_PROVISIONED";
    private static final String MOCK_CERTIFICATE_OWNERSHIP_TOKEN = "MOCK_CERTIFICATE_OWNERSHIP_TOKEN";
    private static final String MOCK_CERTIFICATE_ID = "MOCK_CERTIFICATE_ID";
    private static final String MOCK_CERTIFICATE_PEM = "MOCK_CERTIFICATE_PEM";
    private static final String MOCK_PRIVATE_KEY = "MOCK_PRIVATE_KEY";
    private static final String MOCK_IOT_DATA_ENDPOINT = "MOCK_IOT_DATA_ENDPOINT";
    private static final String MOCK_IOT_CREDENTIAL_ENDPOINT = "MOCK_IOT_CREDENTIAL_ENDPOINT";
    private static final String MOCK_THING_NAME = "MOCK_THING_NAME";
    private static final String MOCK_ROLE_ALIAS = "MOCK_ROLE_ALIAS";
    private static final String MOCK_CLIENT_ID = "MOCK_CLIENT_ID";
    private static final String MOCK_SIGNATURE = "MOCK_SIGNATURE";
    private static final String MOCK_PROVISION_ENDPOINT = "MOCK_PROVISION_ENDPOINT";
    /** Self-signed EC test CA (CN=fb-provision-test-ca, valid 100 years). Only needs to parse. */
    private static final String TEST_CA_PEM = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBlDCCATugAwIBAgIUUyiYQh9WFEeDsSOkhJKiREenU5EwCgYIKoZIzj0EAwIw\n"
            + "HzEdMBsGA1UEAwwUZmItcHJvdmlzaW9uLXRlc3QtY2EwIBcNMjYwOTIxMTIzNzMx\n"
            + "WhgPMjEyNjA4MjgxMjM3MzFaMB8xHTAbBgNVBAMMFGZiLXByb3Zpc2lvbi10ZXN0\n"
            + "LWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+QfkBJKtHPZrXkpoEBm2cAbK\n"
            + "/XgOrRTVe5ICTK167iAT5hNC9BoK5CJAlF9Za/hcVdZzMgAB1/4Fqz8TlWt00KNT\n"
            + "MFEwHQYDVR0OBBYEFLNwCR3aaHazdDt9l7s+oRCCpI2DMB8GA1UdIwQYMBaAFLNw\n"
            + "CR3aaHazdDt9l7s+oRCCpI2DMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID\n"
            + "RwAwRAIgbeAX9nHH8L5F3xhWKrdDJ1tKLCvaXv8qFxxs5pJgHlsCIF77fjAuYXpf\n"
            + "LKyVEzBElDca7n/LE1c+ObeFk+JKiOzs\n"
            + "-----END CERTIFICATE-----\n";

    @TempDir
    Path rootDir;
    Path claimCertificatePath;
    Path privateKeyPath;
    Path signKeyPath;
    Path rootCAPath;

    private FleetProvisioningByClaimPlugin fleetProvisioningByClaimPlugin;

    @Mock
    private IotIdentityHelperFactory iotIdentityHelperFactory;
    @Mock
    private IotIdentityHelper mockIotIdentityHelper;
    @Mock
    private MgmtCloudRouterFactory mgmtCloudRouterFactory;
    @Mock
    private MgmtCloudRouter mockMgmtCloudRouter;
    @Mock
    private MqttConnectionHelper mqttConnectionHelper;
    @Mock
    private MqttClientConnection mockConnection;
    @Mock
    private DeviceIdentityHelper deviceIdentityHelper;

    /**
     * Production retry is unbounded. Tests bound it by interrupting from the
     * sleeper after MAX_TEST_SLEEPS backoffs, which is also the real exit path
     * (nucleus shutdown).
     */
    private static final int MAX_TEST_SLEEPS = 3;
    /** Zero so an incomplete GetEndpoint future times out at once instead of after 900 s. */
    private static final int CLAIM_WAIT_SECONDS = 0;
    private final List<Long> sleeps = new ArrayList<>();
    private final RetryBackoff.Sleeper interruptingSleeper = seconds -> {
        sleeps.add(seconds);
        if (sleeps.size() >= MAX_TEST_SLEEPS) {
            throw new InterruptedException("test: retry budget exhausted");
        }
    };


    /** The MQTT stages need CRT natives. Without them every test here is meaningless: skip visibly. */
    @BeforeAll
    public static void assumeCrtAvailable() {
        try (software.amazon.awssdk.crt.io.EventLoopGroup ignored = new software.amazon.awssdk.crt.io.EventLoopGroup(1)) {
            // available
        } catch (CrtRuntimeException | UnsatisfiedLinkError e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "AWS CRT natives unavailable: " + e.getMessage());
        }
    }

    @BeforeEach
    public void setup(ExtensionContext context) throws Exception {

        claimCertificatePath = rootDir.resolve("claimCert.crt");
        Files.createFile(claimCertificatePath);
        privateKeyPath = rootDir.resolve("privateKey.key");
        Files.createFile(privateKeyPath);
        signKeyPath = rootDir.resolve("signKey.key");
        Files.createFile(signKeyPath);
        // A parseable CA is required: the CRT TLS context is built from it before any
        // mocked stage runs, and an empty file fails with AWS_ERROR_INVALID_ARGUMENT.
        rootCAPath = rootDir.resolve("rootCA.pem");
        Files.write(rootCAPath, TEST_CA_PEM.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        ignoreExceptionUltimateCauseOfType(context, MqttException.class);
        ignoreExceptionUltimateCauseOfType(context, CrtRuntimeException.class);
        fleetProvisioningByClaimPlugin = new FleetProvisioningByClaimPlugin(
                iotIdentityHelperFactory,
                mgmtCloudRouterFactory,
                mqttConnectionHelper,
                deviceIdentityHelper,
                new RetryBackoff(interruptingSleeper),
                CLAIM_WAIT_SECONDS);

        lenient().when(iotIdentityHelperFactory.getInstance(any())).thenReturn(mockIotIdentityHelper);
        lenient().when(mgmtCloudRouterFactory.getInstance(any())).thenReturn(mockMgmtCloudRouter);
        lenient().when(mqttConnectionHelper.getMqttConnection(any())).thenReturn(mockConnection);
        lenient().when(mockConnection.connect()).thenReturn(CompletableFuture.completedFuture(true));
        lenient().when(mockConnection.disconnect()).thenReturn(CompletableFuture.completedFuture(null));
        lenient().when(deviceIdentityHelper.getClientId()).thenReturn(MOCK_CLIENT_ID);
        // readPrivateKey is stubbed to null, and any(Class) does not match null: use any().
        lenient().when(deviceIdentityHelper.sign(anyString(), any())).thenReturn(MOCK_SIGNATURE);
        lenient().when(deviceIdentityHelper.readPrivateKey(any(File.class))).thenReturn(null);

        GetEndpointResponse getEndpointResponse = new GetEndpointResponse();
        getEndpointResponse.iotDataEndpoint = MOCK_IOT_DATA_ENDPOINT;
        getEndpointResponse.iotCredentialsEndpoint = MOCK_IOT_CREDENTIAL_ENDPOINT;
        lenient().when(mockMgmtCloudRouter.getEndpoint(anyString(), anyString()))
                .thenReturn(CompletableFuture.completedFuture(getEndpointResponse));
    }

    @Test
    public void GIVEN_required_params_not_provided_WHEN_plugin_invoked_THEN_validation_fails() {
        Map<String, Object> parameterMap = new HashMap<>();
        // empty map
        Exception e = assertThrows(RuntimeException.class,
                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap)));
        String errorMessage = e.getMessage();
        assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                PROVISIONING_TEMPLATE_PARAMETER_NAME)));
        assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                CLAIM_CERTIFICATE_PATH_PARAMETER_NAME)));
        assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME)));
        assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME)));
        assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                ROOT_CA_PATH_PARAMETER_NAME)));
        assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                ROOT_PATH_PARAMETER_NAME)));
        assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                PROVISION_ENDPOINT_PARAMETER_NAME)));

        // verify optional parameters
        assertFalse(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                TEMPLATE_PARAMETERS_PARAMETER_NAME)));
        assertFalse(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                AWS_REGION_PARAMETER_NAME)));
        assertFalse(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                IOT_ROLE_ALIAS_PARAMETER_NAME)));
    }

    @Test
    public void GIVEN_all_req_parameter_passed_to_plugin_WHEN_plugin_called_THEN_expected_methods_invoked() throws RetryableProvisioningException, InterruptedException {
        Map<String, Object> parameterMap = createRequiredParameterMap();
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        lenient().when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
        lenient().when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN), eq(MOCK_PROV_TEMPLATE_NAME),
            any())).thenReturn(createMockRegisterThingResponse());

        ProvisionConfiguration provisionConfiguration =
                fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext);

        verify(mockMgmtCloudRouter).getEndpoint(eq(MOCK_CLIENT_ID), eq(MOCK_SIGNATURE));
        verify(mockIotIdentityHelper).createKeysAndCertificate();
        verify(mockIotIdentityHelper).registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                eq(MOCK_PROV_TEMPLATE_NAME), any());

        ProvisionConfiguration.SystemConfiguration systemConfiguration =
                provisionConfiguration.getSystemConfiguration();
        assertEquals(Paths.get(rootDir.toString(), DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT).normalize().toString(),
                systemConfiguration.getCertificateFilePath());
        assertEquals(Paths.get(rootDir.toString(), PRIVATE_KEY_PATH_RELATIVE_TO_ROOT).normalize().toString(),
                systemConfiguration.getPrivateKeyPath());

        assertEquals(MOCK_THING_NAME, systemConfiguration.getThingName());
        assertEquals(rootCAPath.toString(), systemConfiguration.getRootCAPath());

        ProvisionConfiguration.NucleusConfiguration nucleusConfiguration =
                provisionConfiguration.getNucleusConfiguration();
        assertEquals(MOCK_IOT_DATA_ENDPOINT, nucleusConfiguration.getIotDataEndpoint());
        assertEquals(MOCK_IOT_CREDENTIAL_ENDPOINT, nucleusConfiguration.getIotCredentialsEndpoint());
    }

    @SuppressWarnings("PMD.LooseCoupling")
    @Test
    public void GIVEN_optional_parameters_passed_to_plugin_WHEN_plugin_called_THEN_expected_methods_invoked() throws RetryableProvisioningException, InterruptedException {
        Map<String, Object> parameterMap = createRequiredParameterMap();
        parameterMap.put(TEMPLATE_PARAMETERS_PARAMETER_NAME, Collections.singletonMap("SerialNumber", 1));
        parameterMap.put(AWS_REGION_PARAMETER_NAME, "us-west-2");
        parameterMap.put(IOT_ROLE_ALIAS_PARAMETER_NAME, MOCK_ROLE_ALIAS);
        parameterMap.put(PROXY_URL_PARAMETER_NAME, "http://testuser:abc123@host:9999");

        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        lenient().when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
        lenient().when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN), eq(MOCK_PROV_TEMPLATE_NAME),
            any())).thenReturn(createMockRegisterThingResponse());

        ProvisionConfiguration provisionConfiguration =
                fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext);

        verify(mockIotIdentityHelper).createKeysAndCertificate();

        ArgumentCaptor<HashMap> templateParameterCaptor = ArgumentCaptor.forClass(HashMap.class);
        verify(mockIotIdentityHelper).registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                eq(MOCK_PROV_TEMPLATE_NAME), templateParameterCaptor.capture());
        assertEquals("1", templateParameterCaptor.getValue().get("SerialNumber"));
        assertEquals(MOCK_CLIENT_ID, templateParameterCaptor.getValue().get("uuid"));
        assertEquals(MOCK_SIGNATURE, templateParameterCaptor.getValue().get("signature"));

        ProvisionConfiguration.NucleusConfiguration nucleusConfiguration =
                provisionConfiguration.getNucleusConfiguration();
        assertEquals(MOCK_IOT_CREDENTIAL_ENDPOINT, nucleusConfiguration.getIotCredentialsEndpoint());
        assertEquals("us-west-2", nucleusConfiguration.getAwsRegion());
        assertEquals(MOCK_ROLE_ALIAS, nucleusConfiguration.getIotRoleAlias());
    }

    @Test
    public void GIVEN_retryable_exception_WHEN_plugin_calls_helper_THEN_retried_with_backoff_until_interrupted(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, InterruptedException.class);
        ignoreExceptionOfType(context, RetryableProvisioningException.class);
        Map<String, Object> parameterMap = createRequiredParameterMap();
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        lenient().when(mockIotIdentityHelper.createKeysAndCertificate())
                .thenThrow(new RetryableProvisioningException("timeout"));

        assertThrows(InterruptedException.class,
                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext));

        // Retried forever with doubling delay; the test sleeper ends it on the third backoff.
        assertEquals(Arrays.asList(20L, 40L, 80L), sleeps);
        verify(mockIotIdentityHelper, times(MAX_TEST_SLEEPS)).createKeysAndCertificate();
    }

    @Test
    public void GIVEN_claim_connect_fails_twice_WHEN_plugin_called_THEN_provisioning_succeeds_on_third_attempt(ExtensionContext context) throws Exception {
        ignoreExceptionUltimateCauseWithMessage(context, "dns failed");
        Map<String, Object> parameterMap = createRequiredParameterMap();
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        CompletableFuture<Boolean> dnsFailure = new CompletableFuture<>();
        dnsFailure.completeExceptionally(new RuntimeException("dns failed"));
        when(mockConnection.connect())
            .thenReturn(dnsFailure)
            .thenReturn(dnsFailure)
            .thenReturn(CompletableFuture.completedFuture(true));
    lenient().when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
    lenient().when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN), eq(MOCK_PROV_TEMPLATE_NAME),
            any())).thenReturn(createMockRegisterThingResponse());

        ProvisionConfiguration provisionConfiguration =
                fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext);

        assertEquals(MOCK_THING_NAME, provisionConfiguration.getSystemConfiguration().getThingName());
        assertEquals(Arrays.asList(20L, 40L), sleeps);
        // The same mock backs every connection: 2 failed claim connects (closed before the
        // next attempt), the successful claim connection, and the phase-2 connection.
        verify(mockConnection, times(4)).close();
        // Every attempt restarts from the identity stage.
        verify(deviceIdentityHelper, times(3)).getClientId();
    }

    @Test
    public void GIVEN_interrupted_exception_WHEN_plugin_calls_helper_THEN_interrupted_exception_thrown(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, InterruptedException.class);
        lenient().when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
        Map<String, Object> parameterMap = createRequiredParameterMap();
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        when(mockIotIdentityHelper.registerThing(any(), any(), any()))
                .thenThrow(new InterruptedException("interrupted"));

        assertThrows(InterruptedException.class,
                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext));
        // An interrupt from inside an attempt propagates without any backoff sleep.
        assertTrue(sleeps.isEmpty(), "expected no backoff sleep, got " + sleeps);
    }

    @Test
    public void GIVEN_endpoint_lookup_fails_twice_WHEN_plugin_called_THEN_attempt_restarts_with_new_connection(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, RetryableProvisioningException.class);
        Map<String, Object> parameterMap = createRequiredParameterMap();
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        GetEndpointResponse endpoints = new GetEndpointResponse();
        endpoints.iotDataEndpoint = MOCK_IOT_DATA_ENDPOINT;
        endpoints.iotCredentialsEndpoint = MOCK_IOT_CREDENTIAL_ENDPOINT;
        // A real failure in the claim stage (subscribe/publish), not the wait timing out.
        when(mockMgmtCloudRouter.getEndpoint(anyString(), anyString()))
                .thenThrow(new RetryableProvisioningException("subscribe timed out"))
                .thenThrow(new RetryableProvisioningException("subscribe timed out"))
                .thenReturn(CompletableFuture.completedFuture(endpoints));
        MqttClientConnection claim1 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        MqttClientConnection claim2 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        MqttClientConnection claim3 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        MqttClientConnection phase2 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        when(mqttConnectionHelper.getMqttConnection(any())).thenReturn(claim1, claim2, claim3, phase2);
        when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
        when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN), eq(MOCK_PROV_TEMPLATE_NAME),
                any())).thenReturn(createMockRegisterThingResponse());

        ProvisionConfiguration provisionConfiguration =
                fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext);

        assertEquals(MOCK_THING_NAME, provisionConfiguration.getSystemConfiguration().getThingName());
        assertEquals(Arrays.asList(20L, 40L), sleeps);
        // No inner wait loop: each failed lookup tears its claim connection down and the
        // next attempt builds a fresh one.
        for (MqttClientConnection claim : Arrays.asList(claim1, claim2, claim3)) {
            verify(claim).disconnect();
            verify(claim).close();
        }
        verify(phase2).disconnect();
    }

    @Test
    public void GIVEN_device_unclaimed_for_full_wait_WHEN_plugin_called_THEN_reconnects_immediately_without_backoff() throws Exception {
        Map<String, Object> parameterMap = createRequiredParameterMap();
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        GetEndpointResponse endpoints = new GetEndpointResponse();
        endpoints.iotDataEndpoint = MOCK_IOT_DATA_ENDPOINT;
        endpoints.iotCredentialsEndpoint = MOCK_IOT_CREDENTIAL_ENDPOINT;
        // Unclaimed: mgmt answers 401 and never completes the future until a claim lands.
        when(mockMgmtCloudRouter.getEndpoint(anyString(), anyString()))
                .thenReturn(new CompletableFuture<>())
                .thenReturn(new CompletableFuture<>())
                .thenReturn(CompletableFuture.completedFuture(endpoints));
        MqttClientConnection claim1 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        MqttClientConnection claim2 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        MqttClientConnection claim3 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        MqttClientConnection phase2 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        when(mqttConnectionHelper.getMqttConnection(any())).thenReturn(claim1, claim2, claim3, phase2);
        when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
        when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN), eq(MOCK_PROV_TEMPLATE_NAME),
                any())).thenReturn(createMockRegisterThingResponse());

        ProvisionConfiguration provisionConfiguration =
                fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext);

        assertEquals(MOCK_THING_NAME, provisionConfiguration.getSystemConfiguration().getThingName());
        // Waiting out the claim window is not a failure: no backoff sleep at all.
        assertTrue(sleeps.isEmpty(), "expected no backoff sleep, got " + sleeps);
        // Each wait ends with a clean teardown and a fresh connection.
        for (MqttClientConnection claim : Arrays.asList(claim1, claim2, claim3)) {
            verify(claim).disconnect();
            verify(claim).close();
        }
        // The identity (TPM setup, signature) is kept across waits, not redone.
        verify(deviceIdentityHelper, times(1)).getClientId();
    }

    @Test
    public void GIVEN_disconnect_fails_after_register_thing_WHEN_plugin_called_THEN_not_registered_again(ExtensionContext context) throws Exception {
        // The failure is logged at WARN and ignored; tell the log protector so.
        ignoreExceptionUltimateCauseWithMessage(context, "link dropped");
        Map<String, Object> parameterMap = createRequiredParameterMap();
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        CompletableFuture<Void> disconnectFailure = new CompletableFuture<>();
        disconnectFailure.completeExceptionally(new RuntimeException("link dropped"));
        MqttClientConnection claim = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        MqttClientConnection phase2 = mockConnectionWithConnect(CompletableFuture.completedFuture(true));
        when(phase2.disconnect()).thenReturn(disconnectFailure);
        when(mqttConnectionHelper.getMqttConnection(any())).thenReturn(claim, phase2);
        when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
        when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN), eq(MOCK_PROV_TEMPLATE_NAME),
                any())).thenReturn(createMockRegisterThingResponse());

        ProvisionConfiguration provisionConfiguration =
                fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext);

        assertEquals(MOCK_THING_NAME, provisionConfiguration.getSystemConfiguration().getThingName());
        verify(mockIotIdentityHelper, times(1)).registerThing(any(), any(), any());
        assertTrue(sleeps.isEmpty(), "expected no retry, got sleeps " + sleeps);
    }

    @Test
    public void GIVEN_local_config_write_fails_after_register_thing_WHEN_plugin_called_THEN_fails_without_retry() throws Exception {
        Map<String, Object> parameterMap = createRequiredParameterMap();
        // rootPath/config must be a directory for the environment file; make it a file so the
        // write after RegisterThing fails while the earlier auth/ writes still succeed.
        Files.createFile(rootDir.resolve("config"));
        ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
        when(mockIotIdentityHelper.createKeysAndCertificate()).thenReturn(createMockCreateKeysAndCertificateResponse());
        when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN), eq(MOCK_PROV_TEMPLATE_NAME),
                any())).thenReturn(createMockRegisterThingResponse());

        assertThrows(DeviceProvisioningRuntimeException.class,
                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext));

        verify(mockIotIdentityHelper, times(1)).registerThing(any(), any(), any());
        assertTrue(sleeps.isEmpty(), "expected no retry, got sleeps " + sleeps);
    }

    private MqttClientConnection mockConnectionWithConnect(CompletableFuture<Boolean> connectResult) {
        MqttClientConnection connection = org.mockito.Mockito.mock(MqttClientConnection.class);
        lenient().when(connection.connect()).thenReturn(connectResult);
        lenient().when(connection.disconnect()).thenReturn(CompletableFuture.completedFuture(null));
        return connection;
    }

    private Future<RegisterThingResponse> createMockRegisterThingResponse() {
        CompletableFuture mockFuture = new CompletableFuture();
        RegisterThingResponse registerThingResponse = new RegisterThingResponse();
        registerThingResponse.thingName = MOCK_THING_NAME;
        registerThingResponse.deviceConfiguration = new HashMap<>();
        registerThingResponse.deviceConfiguration.put("testKey", "testValue");
        mockFuture.complete(registerThingResponse);
        return mockFuture;
    }

    private Future<CreateKeysAndCertificateResponse> createMockCreateKeysAndCertificateResponse() {
        CompletableFuture mockFuture = new CompletableFuture();
        CreateKeysAndCertificateResponse createKeysAndCertificateResponse = new CreateKeysAndCertificateResponse();
        createKeysAndCertificateResponse.certificateId = MOCK_CERTIFICATE_ID;
        createKeysAndCertificateResponse.certificateOwnershipToken = MOCK_CERTIFICATE_OWNERSHIP_TOKEN;
        createKeysAndCertificateResponse.certificatePem = MOCK_CERTIFICATE_PEM;
        createKeysAndCertificateResponse.privateKey = MOCK_PRIVATE_KEY;
        mockFuture.complete(createKeysAndCertificateResponse);
        return mockFuture;
    }

    private Map<String, Object> createRequiredParameterMap() {
        Map<String, Object> parameterMap = new HashMap<>();
        parameterMap.put(PROVISIONING_TEMPLATE_PARAMETER_NAME, MOCK_PROV_TEMPLATE_NAME);
        parameterMap.put(CLAIM_CERTIFICATE_PATH_PARAMETER_NAME, claimCertificatePath.toString());
        parameterMap.put(CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME, privateKeyPath.toString());
        parameterMap.put(SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME, signKeyPath.toString());
        parameterMap.put(ROOT_CA_PATH_PARAMETER_NAME, rootCAPath.toString());
        parameterMap.put(ROOT_PATH_PARAMETER_NAME, rootDir);
        parameterMap.put(PROVISION_ENDPOINT_PARAMETER_NAME, MOCK_PROVISION_ENDPOINT);
        return parameterMap;
    }
}
