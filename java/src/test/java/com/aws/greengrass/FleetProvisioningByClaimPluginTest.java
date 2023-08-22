/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.MqttConnectionHelper.MqttConnectionParameters;
import com.aws.greengrass.model.GetEndpointResponse;
import com.aws.greengrass.provisioning.ProvisionConfiguration;
import com.aws.greengrass.provisioning.ProvisionContext;
import com.aws.greengrass.provisioning.exceptions.RetryableProvisioningException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.crt.http.HttpProxyOptions;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttException;
import software.amazon.awssdk.iot.iotidentity.model.CreateKeysAndCertificateResponse;
import software.amazon.awssdk.iot.iotidentity.model.RegisterThingResponse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import static com.aws.greengrass.FleetProvisioningByClaimPlugin.AWS_REGION_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.CLAIM_CERTIFICATE_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PRIVATE_KEY_PATH_RELATIVE_TO_ROOT;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PROVISIONING_TEMPLATE_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PROVISION_ENDPOINT_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.PROXY_URL_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.ROOT_CA_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.ROOT_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME;
import static com.aws.greengrass.FleetProvisioningByClaimPlugin.TEMPLATE_PARAMETERS_PARAMETER_NAME;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionUltimateCauseOfType;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({ MockitoExtension.class, GGExtension.class })
public class FleetProvisioningByClaimPluginTest {

        private static final String MOCK_PROV_ENDPOINT = "MOCK_PROV_ENDPOINT";
        private static final String MOCK_PROV_TEMPLATE_NAME = "MOCK_PROV_TEMPLATE_NAME";
        private static final String DEFAULT_PROVISIONING_POLICY = "PROVISION_IF_NOT_PROVISIONED";
        private static final String MOCK_CERTIFICATE_OWNERSHIP_TOKEN = "MOCK_CERTIFICATE_OWNERSHIP_TOKEN";
        private static final String MOCK_CERTIFICATE_ID = "MOCK_CERTIFICATE_ID";
        private static final String MOCK_CERTIFICATE_PEM = "MOCK_CERTIFICATE_PEM";
        private static final String MOCK_PRIVATE_KEY = "MOCK_PRIVATE_KEY";
        private static final String MOCK_IOT_DATA_ENDPOINT = "MOCK_IOT_DATA_ENDPOINT";
        private static final String MOCK_THING_NAME = "MOCK_THING_NAME";
        private static final String MOCK_IOT_CREDENTIAL_ENDPOINT = "MOCK_IOT_CREDENTIAL_ENDPOINT";
        private static final String MOCK_SIGNATURE = "MOCK_SIGNATURE";

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
        private MgmtCloudRouterFactory mgmtCloudRouterFactory;
        @Mock
        private MgmtCloudRouter mockMgmtCloudRouter;
        @Mock
        private IotIdentityHelper mockIotIdentityHelper;
        @Mock
        private MqttConnectionHelper mqttConnectionHelper;
        @Mock
        private MqttClientConnection mockConnection;
        @Mock
        private DeviceIdentityHelper mockDeviceIdentityHelper;

        @BeforeEach
        public void setup(ExtensionContext context) throws IOException, GeneralSecurityException {

                claimCertificatePath = rootDir.resolve("claimCert.crt");
                Files.createFile(claimCertificatePath);
                privateKeyPath = rootDir.resolve("privateKey.key");
                Files.createFile(privateKeyPath);
                signKeyPath = rootDir.resolve("sign.key");
                Files.createFile(signKeyPath);
                rootCAPath = rootDir.resolve("rootCA.pem");
                Files.createFile(rootCAPath);

                ignoreExceptionUltimateCauseOfType(context, MqttException.class);
                fleetProvisioningByClaimPlugin = new FleetProvisioningByClaimPlugin(iotIdentityHelperFactory,
                                mgmtCloudRouterFactory, mqttConnectionHelper, mockDeviceIdentityHelper);
                lenient().when(iotIdentityHelperFactory.getInstance(any())).thenReturn(mockIotIdentityHelper);
                lenient().when(mgmtCloudRouterFactory.getInstance(any())).thenReturn(mockMgmtCloudRouter);
                lenient().when(mqttConnectionHelper.getMqttConnection(any()))
                                .thenReturn(mockConnection);
                lenient().when(mockConnection.connect()).thenReturn(CompletableFuture.completedFuture(true));
                lenient().when(mockConnection.disconnect()).thenReturn(CompletableFuture.completedFuture(null));

                lenient().when(mockDeviceIdentityHelper.getClientId()).thenReturn(MOCK_THING_NAME);
                lenient().when(mockDeviceIdentityHelper.readPrivateKey(any()))
                                .thenReturn(mock(PrivateKey.class));
                lenient().when(mockDeviceIdentityHelper.sign(eq(MOCK_THING_NAME), any())).thenReturn(MOCK_SIGNATURE);
        }

        @Test
        public void GIVEN_required_params_not_provided_WHEN_plugin_invoked_THEN_validation_fails() {
                Map<String, Object> parameterMap = new HashMap<>();
                // empty map
                Exception e = assertThrows(RuntimeException.class,
                                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(
                                                new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap)));
                String errorMessage = e.getMessage();
                assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                                PROVISIONING_TEMPLATE_PARAMETER_NAME)));
                assertTrue(errorMessage.contains(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                                PROVISION_ENDPOINT_PARAMETER_NAME)));
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
        }

        @Test
        public void GIVEN_all_req_parameter_passed_to_plugin_WHEN_plugin_called_THEN_expected_methods_invoked()
                        throws RetryableProvisioningException, InterruptedException, IOException {
                Map<String, Object> parameterMap = createRequiredParameterMap();
                ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
                when(mockMgmtCloudRouter.getEndpoint(eq(MOCK_THING_NAME), any()))
                                .thenReturn(createMockGetEndpointRequest());
                when(mockIotIdentityHelper.createKeysAndCertificate())
                                .thenReturn(createMockCreateKeysAndCertificateResponse());
                when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                                eq(MOCK_PROV_TEMPLATE_NAME),
                                any())).thenReturn(createMockRegisterThingResponse());

                ProvisionConfiguration provisionConfiguration = fleetProvisioningByClaimPlugin
                                .updateIdentityConfiguration(provisionContext);

                verify(mockIotIdentityHelper).createKeysAndCertificate();
                verify(mockIotIdentityHelper).registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                                eq(MOCK_PROV_TEMPLATE_NAME), any());

                ProvisionConfiguration.SystemConfiguration systemConfiguration = provisionConfiguration
                                .getSystemConfiguration();
                assertEquals(Paths.get(rootDir.toString(), DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT).normalize()
                                .toString(),
                                systemConfiguration.getCertificateFilePath());
                assertEquals(Paths.get(rootDir.toString(), PRIVATE_KEY_PATH_RELATIVE_TO_ROOT).normalize().toString(),
                                systemConfiguration.getPrivateKeyPath());
                assertEquals(MOCK_THING_NAME, systemConfiguration.getThingName());
                assertEquals(rootCAPath.toString(), systemConfiguration.getRootCAPath());

                ProvisionConfiguration.NucleusConfiguration nucleusConfiguration = provisionConfiguration
                                .getNucleusConfiguration();
                assertEquals(MOCK_IOT_DATA_ENDPOINT,
                                nucleusConfiguration.getIotDataEndpoint());
        }

        @Test
        public void GIVEN_optional_parameters_passed_to_plugin_WHEN_plugin_called_THEN_expected_methods_invoked()
                        throws RetryableProvisioningException, InterruptedException {
                Map<String, Object> parameterMap = createRequiredParameterMap();
                parameterMap.put(TEMPLATE_PARAMETERS_PARAMETER_NAME,
                                Collections.singletonMap("SerialNumber", 1));
                parameterMap.put(AWS_REGION_PARAMETER_NAME, "us-west-2");
                parameterMap.put(PROXY_URL_PARAMETER_NAME,
                                "http://testuser:abc123@host:9999");

                ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
                when(mockMgmtCloudRouter.getEndpoint(eq(MOCK_THING_NAME), any()))
                                .thenReturn(createMockGetEndpointRequest());
                when(mockIotIdentityHelper.createKeysAndCertificate())
                                .thenReturn(createMockCreateKeysAndCertificateResponse());
                when(mockIotIdentityHelper.registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                                eq(MOCK_PROV_TEMPLATE_NAME),
                                any())).thenReturn(createMockRegisterThingResponse());

                ProvisionConfiguration provisionConfiguration = fleetProvisioningByClaimPlugin
                                .updateIdentityConfiguration(provisionContext);
                // ArgumentCaptor<MqttConnectionParameters> mqttParameterCaptor = ArgumentCaptor
                //                 .forClass(MqttConnectionParameters.class);
                // verify(mqttConnectionHelper).getMqttConnection(mqttParameterCaptor.capture());
                verify(mockIotIdentityHelper).createKeysAndCertificate();

                ArgumentCaptor<HashMap> templateParameterCaptor = ArgumentCaptor.forClass(HashMap.class);
                verify(mockIotIdentityHelper).registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                                eq(MOCK_PROV_TEMPLATE_NAME), templateParameterCaptor.capture());
                assertEquals("1", templateParameterCaptor.getValue().get("SerialNumber"));

                ProvisionConfiguration.NucleusConfiguration nucleusConfiguration = provisionConfiguration
                                .getNucleusConfiguration();
                assertEquals(MOCK_IOT_CREDENTIAL_ENDPOINT,
                                nucleusConfiguration.getIotCredentialsEndpoint());
                assertEquals("us-west-2", nucleusConfiguration.getAwsRegion());
                // assertEquals(MOCK_ROLE_ALIAS, nucleusConfiguration.getIotRoleAlias());
                // HttpProxyOptions httpProxyOptions = mqttParameterCaptor.getValue().getHttpProxyOptions();
                // assertEquals("host", httpProxyOptions.getHost());
                // assertEquals(9999, httpProxyOptions.getPort());
                // assertEquals("testuser", httpProxyOptions.getAuthorizationUsername());
                // assertEquals("abc123", httpProxyOptions.getAuthorizationPassword());

        }

        @Test
        public void GIVEN_invalid_endpoint_passed_to_plugin_WHEN_plugin_called_THEN_runtime_exception()
                        throws RetryableProvisioningException, InterruptedException {
                Map<String, Object> parameterMap = createRequiredParameterMap();
                CompletableFuture<Boolean> completableFuture = new CompletableFuture<Boolean>();
                completableFuture.completeExceptionally(new MqttException("Invalid Exception"));
                when(mockConnection.connect()).thenReturn(completableFuture);
                ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);

                assertThrows(RuntimeException.class,
                                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext));
                verify(mockIotIdentityHelper, times(0)).createKeysAndCertificate();
                verify(mockIotIdentityHelper,
                                times(0)).registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                                                eq(MOCK_PROV_TEMPLATE_NAME), any());
        }

        @Test
        public void GIVEN_retryable_exception_WHEN_plugin_calls_helper_THEN_retryable_exception_thrown()
                        throws Exception {
                Map<String, Object> parameterMap = createRequiredParameterMap();
                when(mockConnection.connect()).thenReturn(CompletableFuture.completedFuture(true));
                ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
                when(mockMgmtCloudRouter.getEndpoint(eq(MOCK_THING_NAME), any()))
                                .thenReturn(createMockGetEndpointRequest());
                when(mockIotIdentityHelper.createKeysAndCertificate())
                                .thenThrow(new RetryableProvisioningException("timeout"));
                assertThrows(RetryableProvisioningException.class,
                                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext));
                verify(mockIotIdentityHelper).createKeysAndCertificate();
                verify(mockIotIdentityHelper,
                                times(0)).registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                                                eq(MOCK_PROV_TEMPLATE_NAME), any());
        }

        @Test
        public void GIVEN_interrupted_exception_WHEN_plugin_calls_helper_THEN_interrupted_exception_thrown(
                        ExtensionContext context) throws Exception {
                ignoreExceptionOfType(context, InterruptedException.class);
                when(mockMgmtCloudRouter.getEndpoint(eq(MOCK_THING_NAME), any()))
                                .thenReturn(createMockGetEndpointRequest());
                when(mockIotIdentityHelper.createKeysAndCertificate())
                                .thenReturn(createMockCreateKeysAndCertificateResponse());
                Map<String, Object> parameterMap = createRequiredParameterMap();
                when(mockConnection.connect()).thenReturn(CompletableFuture.completedFuture(true));
                ProvisionContext provisionContext = new ProvisionContext(DEFAULT_PROVISIONING_POLICY, parameterMap);
                when(mockIotIdentityHelper.registerThing(any(), any(), any()))
                                .thenThrow(new InterruptedException("interrupted"));
                assertThrows(InterruptedException.class,
                                () -> fleetProvisioningByClaimPlugin.updateIdentityConfiguration(provisionContext));
                verify(mockIotIdentityHelper).createKeysAndCertificate();
                verify(mockIotIdentityHelper).registerThing(eq(MOCK_CERTIFICATE_OWNERSHIP_TOKEN),
                                eq(MOCK_PROV_TEMPLATE_NAME), any());
        }

        private Future<RegisterThingResponse> createMockRegisterThingResponse() {
                CompletableFuture<RegisterThingResponse> mockFuture = new CompletableFuture<RegisterThingResponse>();
                RegisterThingResponse registerThingResponse = new RegisterThingResponse();
                registerThingResponse.thingName = MOCK_THING_NAME;
                mockFuture.complete(registerThingResponse);
                return mockFuture;
        }

        private Future<GetEndpointResponse> createMockGetEndpointRequest() {
                CompletableFuture<GetEndpointResponse> mockFuture = new CompletableFuture<GetEndpointResponse>();
                GetEndpointResponse getEndpointResponse = new GetEndpointResponse();
                getEndpointResponse.iotCredentialsEndpoint = MOCK_IOT_CREDENTIAL_ENDPOINT;
                getEndpointResponse.iotDataEndpoint = MOCK_IOT_DATA_ENDPOINT;
                mockFuture.complete(getEndpointResponse);
                return mockFuture;
        }

        private Future<CreateKeysAndCertificateResponse> createMockCreateKeysAndCertificateResponse() {
                CompletableFuture<CreateKeysAndCertificateResponse> mockFuture = new CompletableFuture<CreateKeysAndCertificateResponse>();
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
                parameterMap.put(PROVISION_ENDPOINT_PARAMETER_NAME, MOCK_PROV_ENDPOINT);
                parameterMap.put(CLAIM_CERTIFICATE_PATH_PARAMETER_NAME, claimCertificatePath.toString());
                parameterMap.put(CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME, privateKeyPath.toString());
                parameterMap.put(SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME, signKeyPath.toString());
                parameterMap.put(ROOT_CA_PATH_PARAMETER_NAME, rootCAPath.toString());
                parameterMap.put(ROOT_PATH_PARAMETER_NAME, rootDir);
                return parameterMap;
        }
}
