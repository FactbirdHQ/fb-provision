/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.MqttConnectionHelper.MqttConnectionParameters.MqttConnectionParametersBuilder;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.model.GetEndpointResponse;
import com.aws.greengrass.pkcs.PkcsProvider;
import com.aws.greengrass.provisioning.DeviceIdentityInterface;
import com.aws.greengrass.provisioning.ProvisionConfiguration;
import com.aws.greengrass.provisioning.ProvisionConfiguration.NucleusConfiguration;
import com.aws.greengrass.provisioning.ProvisionConfiguration.SystemConfiguration;
import com.aws.greengrass.provisioning.ProvisionContext;
import com.aws.greengrass.provisioning.exceptions.RetryableProvisioningException;
import com.aws.greengrass.util.FileSystemPermission;
import com.aws.greengrass.util.Utils;
import com.aws.greengrass.util.platforms.Platform;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import software.amazon.awssdk.crt.http.HttpProxyOptions;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.ClientTlsContext;
import software.amazon.awssdk.crt.io.EventLoopGroup;
import software.amazon.awssdk.crt.io.HostResolver;
import software.amazon.awssdk.crt.io.TlsContext;
import software.amazon.awssdk.crt.io.TlsContextOptions;
import software.amazon.awssdk.crt.io.TlsContextPkcs11Options;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.iot.iotidentity.model.CreateCertificateFromCsrResponse;
import software.amazon.awssdk.iot.iotidentity.model.CreateKeysAndCertificateResponse;
import software.amazon.awssdk.iot.iotidentity.model.RegisterThingResponse;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class FleetProvisioningByClaimPlugin implements DeviceIdentityInterface {

        static final String PLUGIN_NAME = "aws.greengrass.FleetProvisioningByClaim";
        private static final Logger logger = LogManager.getLogger(FleetProvisioningByClaimPlugin.class);

        // Required parameters
        static final String PROVISION_ENDPOINT_PARAMETER_NAME = "provisionEndpoint";
        static final String PROVISIONING_TEMPLATE_PARAMETER_NAME = "provisioningTemplate";
        static final String CLAIM_CERTIFICATE_PATH_PARAMETER_NAME = "claimCertificatePath";
        static final String CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME = "claimCertificatePrivateKeyPath";
        static final String SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME = "signPrivateKeyPath";
        static final String ROOT_CA_PATH_PARAMETER_NAME = "rootCaPath";
        static final String ROOT_PATH_PARAMETER_NAME = "rootPath";
        static final String MQTT_PORT_PARAMETER_NAME = "mqttPort";

        static final String USE_TPM_PROV_PARAMETER_NAME = "useTpmProvisioning";
        static final String PKCS11_LIBRARY_PARAMETER_NAME = "pkcs11Library";
        static final String PKCS11_SLOT_PARAMETER_NAME = "pkcs11Slot";
        static final String PKCS11_USER_PIN_PARAMETER_NAME = "pkcs11UserPin";

        // Optional Paramters
        static final String TEMPLATE_PARAMETERS_PARAMETER_NAME = "templateParameters";
        static final String AWS_REGION_PARAMETER_NAME = "awsRegion";
        static final String IOT_ROLE_ALIAS_PARAMETER_NAME = "iotRoleAlias";
        static final String PROXY_URL_PARAMETER_NAME = "proxyUrl";
        static final String PROXY_USERNAME_PARAMETER_NAME = "proxyUsername";
        static final String PROXY_PASSWORD_PARAMETER_NAME = "proxyPassword";
         

        static final String MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT = "Required parameter %s missing for "
                        + PLUGIN_NAME;

        static final String DEVICE_CONFIGURATION_PATH_RELATIVE_TO_ROOT = "/config/device_config.json";
        static final String DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT = "/auth/prov.cert.pem";
        static final String PRIVATE_KEY_PATH_RELATIVE_TO_ROOT = "/auth/prov.pkey.pem";

        static final String AUTH_KEY_LABEL = "auth";

        private final IotIdentityHelperFactory iotIdentityHelperFactory;
        private final MgmtCloudRouterFactory mgmtCloudRouterFactory;
        private final MqttConnectionHelper mqttConnectionHelper;
        private final DeviceIdentityHelper deviceIdentityHelper;
        private final RetryBackoff retryBackoff;
        /** How long one claim connection waits for mgmt to answer GetEndpoint before reconnecting. */
        private final int claimWaitSeconds;
        static final int DEFAULT_CLAIM_WAIT_SECONDS = 900;

        /** Run AWS Fleet provisioning by claim flow.
         * 
         */
        public FleetProvisioningByClaimPlugin() {
                this(new IotIdentityHelperFactory(), new MgmtCloudRouterFactory(), new MqttConnectionHelper(),
                                new DeviceIdentityHelper(), new RetryBackoff(), DEFAULT_CLAIM_WAIT_SECONDS);
        }

        FleetProvisioningByClaimPlugin(IotIdentityHelperFactory iotIdentityHelperFactory,
                        MgmtCloudRouterFactory mgmtCloudRouterFactory,
                        MqttConnectionHelper mqttConnectionHelper,
                        DeviceIdentityHelper deviceIdentityHelper,
                        RetryBackoff retryBackoff,
                        int claimWaitSeconds) {
                this.iotIdentityHelperFactory = iotIdentityHelperFactory;
                this.mgmtCloudRouterFactory = mgmtCloudRouterFactory;
                this.mqttConnectionHelper = mqttConnectionHelper;
                this.deviceIdentityHelper = deviceIdentityHelper;
                this.retryBackoff = retryBackoff;
                this.claimWaitSeconds = claimWaitSeconds;
        }

        @Override
        public String name() {
                return PLUGIN_NAME;
        }

        @Override
        public ProvisionConfiguration updateIdentityConfiguration(ProvisionContext provisionContext)
                        throws RetryableProvisioningException, InterruptedException {

                logger.atInfo().kv("version", pluginVersion())
                                .log("FleetProvisioningByClaimPlugin starting: unbounded provisioning retry with backoff");

                Map<String, Object> parameterMap = provisionContext.getParameterMap();
                validateParameters(parameterMap);
                ProvisioningParameters params = ProvisioningParameters.from(parameterMap);

                // One attempt = TPM setup, claim, registration. Any failure tears everything
                // down and starts over after a backoff, forever. The nucleus only re-invokes the
                // plugin 3 times seconds apart (and only for RetryableProvisioningException), so a
                // give-up here means an unprovisioned boot until the next process restart.
                RegisteredDevice registered = retryBackoff.runForever("provisioning", () -> attemptProvisioning(params));

                // Past this point the thing is registered in IoT with an active certificate.
                // A failure here must not re-run registration (it would mint a second one), so
                // the local config write is deliberately outside the retry loop.
                return createProvisioningConfiguration(params.parameterMap, registered.iotDataEndpoint,
                                registered.iotCredentialsEndpoint, registered.registerThingResponse);
        }

        /** A single end-to-end provisioning attempt. Every resource it opens is closed before it returns. */
        private RegisteredDevice attemptProvisioning(ProvisioningParameters params) throws Exception {
                // Stage 1: TPM/PKCS11 setup + clientId signature.
                DeviceIdentity identity = createIdentity(params);
                try {
                        MqttConnectionParametersBuilder mqttParameterBuilder = buildMqttParameters(params, identity);

                        // Stage 2: claim endpoint → tenant endpoints. Blocks while unclaimed.
                        GetEndpointResponse endpoints = waitForClaim(params, identity, mqttParameterBuilder);

                        // Stage 3: connect to the provisioned endpoint, create the device certificate
                        // and register the thing.
                        logger.atInfo().log("Starting second MQTT connection to provisioned IoT endpoint: {}",
                                        endpoints.iotDataEndpoint);
                        return registerDevice(params, identity, mqttParameterBuilder, endpoints);
                } finally {
                        identity.close();
                }
        }

        /**
         * Stage 2: connect to the claim endpoint and ask mgmt for the tenant endpoints. Mgmt answers
         * at once for a claimed device and pushes later when an unclaimed one gets claimed. Each
         * connection waits claimWaitSeconds, then is replaced immediately with the same identity: a
         * silently dead MQTT session cannot trap us, a claim is picked up within seconds, and the TPM
         * stage is not redone every cycle. Anything other than the wait timing out is a real failure
         * and propagates to the outer backoff.
         */
        private GetEndpointResponse waitForClaim(ProvisioningParameters params, DeviceIdentity identity,
                        MqttConnectionParametersBuilder mqttParameterBuilder) throws Exception {
                while (true) {
                        logger.atInfo().log("Starting first MQTT connection to provision endpoint: {}", params.provisionEndpoint);
                        try (EventLoopGroup eventLoopGroup = new EventLoopGroup(1);
                                        HostResolver resolver = new HostResolver(eventLoopGroup);
                                        ClientBootstrap clientBootstrap = new ClientBootstrap(eventLoopGroup, resolver)) {

                                MqttClientConnection mgmtConnection = connectToClaimEndpoint(mqttParameterBuilder
                                                .endpoint(params.provisionEndpoint)
                                                .clientBootstrap(clientBootstrap).build());
                                try {
                                        logger.atInfo().log("MQTT connection establishment. Getting claim status");
                                        return getClaimedEndpoint(mgmtConnection, identity);
                                } catch (ClaimWaitTimeout e) {
                                        logger.atInfo().log("No claim after {} s, reconnecting to wait again", claimWaitSeconds);
                                } finally {
                                        disconnectAndClose(mgmtConnection);
                                }
                        }
                }
        }

        /**
         * Stage 1: open the PKCS11 provider (TPM flow), resolve the device clientId
         * and sign it. On any failure the provider is torn down so the next attempt
         * starts from a clean SunPKCS11 registration.
         */
        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private DeviceIdentity createIdentity(ProvisioningParameters params) throws Exception {
                PkcsProvider pkcsProvider = null;
                try {
                        String signKeyLabel = null;
                        String claimKeyLabel = null;
                        if (params.useTpmProvisioning) {
                                pkcsProvider = new PkcsProvider(params.pkcs11Library, params.pkcs11UserPin,
                                                params.pkcs11Slot, AUTH_KEY_LABEL);
                                signKeyLabel = pkcsProvider.extractObjectLabel(params.signKeyPath);
                                claimKeyLabel = pkcsProvider.extractObjectLabel(params.certPath);
                                if (signKeyLabel == null || claimKeyLabel == null) {
                                        throw new DeviceProvisioningRuntimeException("Failed to extract key labels from URI's");
                                }
                        }

                        String clientId = this.deviceIdentityHelper.getClientId();
                        String signature;
                        if (params.useTpmProvisioning) {
                                signature = pkcsProvider.sign(clientId, signKeyLabel);
                        } else {
                                PrivateKey privKey = this.deviceIdentityHelper.readPrivateKey(new File(params.signKeyPath));
                                signature = this.deviceIdentityHelper.sign(clientId, privKey);
                        }
                        TlsContextPkcs11Options tlsPkcsOptions = params.useTpmProvisioning
                                        ? pkcsProvider.createTlsContextPkcs11Options(claimKeyLabel)
                                        : null;
                        return new DeviceIdentity(clientId, signature, pkcsProvider, tlsPkcsOptions);
                } catch (Exception e) {
                        if (pkcsProvider != null) {
                                closeQuietly(pkcsProvider);
                        }
                        throw e;
                }
        }

        private static MqttConnectionParametersBuilder buildMqttParameters(ProvisioningParameters params,
                        DeviceIdentity identity) {
                return MqttConnectionHelper.MqttConnectionParameters
                                .builder()
                                .certificateUri(params.certPath)
                                .privKeyUri(params.keyPath)
                                .rootCaPath(params.rootCaPath)
                                .clientId(identity.clientId)
                                .tlsPkcsOptions(identity.tlsPkcsOptions)
                                .httpProxyOptions(params.httpProxyOptions)
                                .mqttPort(params.mqttPort);
        }

        /** Stage 2: create and connect the claim MQTT connection; closed on failure. */
        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private MqttClientConnection connectToClaimEndpoint(MqttConnectionHelper.MqttConnectionParameters parameters)
                        throws Exception {
                MqttClientConnection connection = mqttConnectionHelper.getMqttConnection(parameters);
                try {
                        CompletableFuture<Boolean> connected = connection.connect();
                        FutureExceptionHandler.getFutureAfterCompletion(connected,
                            "Caught exception while establishing connection to AWS Iot");
                        logger.atInfo().log("Successfully established MQTT connection to provision endpoint");
                        return connection;
                } catch (Exception e) {
                        closeQuietly(connection);
                        throw e;
                }
        }

        /**
         * Subscribe and publish GetEndpoint (failures here are real and back off), then wait
         * for mgmt's answer. Mgmt replies at once for a claimed device and pushes later when an
         * unclaimed one gets claimed, so a timeout only means "still not claimed".
         */
        private GetEndpointResponse getClaimedEndpoint(MqttClientConnection connection, DeviceIdentity identity)
                        throws InterruptedException, RetryableProvisioningException, ClaimWaitTimeout {
                MgmtCloudRouter mgmtCloudRouter = mgmtCloudRouterFactory.getInstance(connection);
                Future<GetEndpointResponse> endpoint = mgmtCloudRouter.getEndpoint(identity.clientId, identity.signature);
                try {
                        return endpoint.get(claimWaitSeconds, TimeUnit.SECONDS);
                } catch (TimeoutException e) {
                        throw new ClaimWaitTimeout();
                } catch (ExecutionException e) {
                        throw new RetryableProvisioningException(e.getCause());
                }
        }

        /** Stage 3: second connection, certificate creation, RegisterThing. */
        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private RegisteredDevice registerDevice(ProvisioningParameters params, DeviceIdentity identity,
                        MqttConnectionParametersBuilder mqttParameterBuilder, GetEndpointResponse endpoints)
                        throws Exception {
                String provisionedIotDataEndpoint = endpoints.iotDataEndpoint;
                try (EventLoopGroup eventLoopGroup = new EventLoopGroup(1);
                                HostResolver resolver = new HostResolver(eventLoopGroup);
                                ClientBootstrap clientBootstrap = new ClientBootstrap(eventLoopGroup, resolver);

                                MqttClientConnection connection = mqttConnectionHelper
                                                .getMqttConnection(mqttParameterBuilder
                                                                .endpoint(provisionedIotDataEndpoint)
                                                                .clientBootstrap(clientBootstrap).build())) {

                        // Setup new connection to `provisionedIotDataEndpoint`
                        CompletableFuture<Boolean> connected = connection.connect();
                        FutureExceptionHandler.getFutureAfterCompletion(connected,
                            "Caught exception while establishing connection to AWS Iot");

                        IotIdentityHelper iotIdentityHelper = iotIdentityHelperFactory.getInstance(connection);

                        String certificateOwnershipToken;

                        if (params.useTpmProvisioning) {
                                logger.atInfo().log("Provisioning with CSR flow");

                                // A retried attempt regenerates the key; setKeyEntry below replaces any
                                // earlier "auth" private key + cert under the same alias (verified on
                                // device). Only the session public key can be left behind, at most one
                                // per attempt that fails between here and RegisterThing.
                                KeyPair authKeys = identity.pkcsProvider.generateKeyPair();

                                // Create CSR
                                String csr = identity.pkcsProvider.generateCSR(identity.clientId, authKeys);

                                CreateCertificateFromCsrResponse response;
                                response = FutureExceptionHandler.getFutureAfterCompletion(
                                    iotIdentityHelper.createCertificateFromCsr(csr),
                                    "Caught exception during PublishCreateCertificateFromCsr");

                                // write certificate to the keystore
                                identity.pkcsProvider.addCertificateToKeystore(
                                    AUTH_KEY_LABEL, authKeys, response.certificatePem);

                                certificateOwnershipToken = response.certificateOwnershipToken;

                        } else {
                                logger.atInfo().log("Provisioning with certificates from filespaths");
                                CreateKeysAndCertificateResponse response;
                                response = FutureExceptionHandler.getFutureAfterCompletion(
                                    iotIdentityHelper.createKeysAndCertificate(),
                                    "Caught exception during PublishCreateKeysAndCertificate");

                                writeCertificateAndKeyToPath(response, params.rootPath);
                                certificateOwnershipToken = response.certificateOwnershipToken;
                        }

                        HashMap<String, String> parameterHashMap = new HashMap<>();
                        if (params.templateParameters != null) {
                                params.templateParameters.forEach((k, v) -> parameterHashMap.put(k, v.toString()));
                        }
                        // Add uuid & signature
                        parameterHashMap.put("uuid", identity.clientId);
                        parameterHashMap.put("signature", identity.signature);

                        Future<RegisterThingResponse> registerFuture = iotIdentityHelper
                            .registerThing(certificateOwnershipToken, params.templateName, parameterHashMap);
                        RegisterThingResponse registerThingResponse = FutureExceptionHandler
                            .getFutureAfterCompletion(registerFuture,
                                "Caught exception during registering Iot Thing");

                        // The thing is registered. From here on nothing may fail the attempt, or the
                        // retry would register again with a second active certificate.
                        try {
                                CompletableFuture<Void> disconnected = connection.disconnect();
                                FutureExceptionHandler.getFutureAfterCompletion(disconnected,
                                    "Caught exception while disconnecting");
                        } catch (InterruptedException e) {
                                throw e;
                        } catch (Exception e) {
                                logger.atWarn().setCause(e).log("Disconnect after RegisterThing failed; ignoring");
                        }

                        return new RegisteredDevice(endpoints, registerThingResponse);
                }
        }

        /** Thrown when a claim connection has waited its full window without an answer. */
        private static final class ClaimWaitTimeout extends Exception {
                private static final long serialVersionUID = 1L;
        }

        /** Outcome of a successful attempt: what the nucleus config is built from. */
        private static final class RegisteredDevice {
                final String iotDataEndpoint;
                final String iotCredentialsEndpoint;
                final RegisterThingResponse registerThingResponse;

                RegisteredDevice(GetEndpointResponse endpoints, RegisterThingResponse registerThingResponse) {
                        this.iotDataEndpoint = endpoints.iotDataEndpoint;
                        this.iotCredentialsEndpoint = endpoints.iotCredentialsEndpoint;
                        this.registerThingResponse = registerThingResponse;
                }
        }

        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private static void disconnectAndClose(MqttClientConnection connection) throws InterruptedException {
                try {
                        CompletableFuture<Void> disconnected = connection.disconnect();
                        FutureExceptionHandler.getFutureAfterCompletion(disconnected,
                            "Caught exception while disconnecting");
                } catch (InterruptedException e) {
                        throw e;
                } catch (Exception e) {
                        logger.atWarn().setCause(e).log("Exception while disconnecting claim connection");
                } finally {
                        closeQuietly(connection);
                }
        }

        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private static void closeQuietly(MqttClientConnection connection) {
                try {
                        connection.close();
                } catch (Exception e) {
                        logger.atWarn().setCause(e).log("Exception while closing connection");
                }
        }

        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private static void closeQuietly(PkcsProvider pkcsProvider) {
                try {
                        pkcsProvider.close();
                } catch (Exception e) {
                        logger.atWarn().setCause(e).log("Exception while closing PKCS11 provider");
                }
        }

        /** Parsed plugin parameters; built once, outside every retry loop. */
        private static final class ProvisioningParameters {
                final Map<String, Object> parameterMap;
                final String certPath;
                final String keyPath;
                final String signKeyPath;
                final Integer mqttPort;
                final String provisionEndpoint;
                final boolean useTpmProvisioning;
                final String pkcs11Library;
                final String pkcs11Slot;
                final String pkcs11UserPin;
                final String rootCaPath;
                final String rootPath;
                final String templateName;
                final HttpProxyOptions httpProxyOptions;
                final Map<String, Object> templateParameters;

                @SuppressWarnings("unchecked")
                private ProvisioningParameters(Map<String, Object> parameterMap) {
                        this.parameterMap = parameterMap;
                        certPath = parameterMap.get(CLAIM_CERTIFICATE_PATH_PARAMETER_NAME).toString();
                        keyPath = parameterMap.get(CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME).toString();
                        signKeyPath = parameterMap.get(SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME).toString();
                        mqttPort = parameterMap.get(MQTT_PORT_PARAMETER_NAME) == null ? null
                                        : Integer.valueOf(parameterMap.get(MQTT_PORT_PARAMETER_NAME).toString());
                        provisionEndpoint = parameterMap.get(PROVISION_ENDPOINT_PARAMETER_NAME).toString();
                        useTpmProvisioning = parseBoolean(parameterMap.get(USE_TPM_PROV_PARAMETER_NAME));
                        pkcs11Library = optional(parameterMap, PKCS11_LIBRARY_PARAMETER_NAME);
                        pkcs11Slot = optional(parameterMap, PKCS11_SLOT_PARAMETER_NAME);
                        pkcs11UserPin = optional(parameterMap, PKCS11_USER_PIN_PARAMETER_NAME);
                        rootCaPath = parameterMap.get(ROOT_CA_PATH_PARAMETER_NAME).toString();
                        rootPath = parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString();
                        templateName = parameterMap.get(PROVISIONING_TEMPLATE_PARAMETER_NAME).toString();
                        TlsContext proxyTlsContext = new ClientTlsContext(getTlsContextOptions(rootCaPath));
                        httpProxyOptions = MqttConnectionHelper.getHttpProxyOptions(
                                        optional(parameterMap, PROXY_URL_PARAMETER_NAME),
                                        optional(parameterMap, PROXY_USERNAME_PARAMETER_NAME),
                                        optional(parameterMap, PROXY_PASSWORD_PARAMETER_NAME),
                                        proxyTlsContext);
                        templateParameters = (Map<String, Object>) parameterMap.get(TEMPLATE_PARAMETERS_PARAMETER_NAME);
                }

                static ProvisioningParameters from(Map<String, Object> parameterMap) {
                        return new ProvisioningParameters(parameterMap);
                }

                private static String optional(Map<String, Object> parameterMap, String key) {
                        return parameterMap.get(key) == null ? null : parameterMap.get(key).toString();
                }

                private static boolean parseBoolean(Object value) {
                        if (value == null) {
                                return false;
                        }
                        if (value instanceof Boolean) {
                                return (Boolean) value;
                        }
                        return Boolean.parseBoolean(value.toString());
                }
        }

        /**
         * Result of the identity stage: who the device is, proven by a signature, plus the
         * native PKCS11 handles (TLS options pin the CRT lib) that live exactly as long as it.
         */
        private static final class DeviceIdentity {
                final String clientId;
                final String signature;
                final PkcsProvider pkcsProvider;
                final TlsContextPkcs11Options tlsPkcsOptions;

                DeviceIdentity(String clientId, String signature, PkcsProvider pkcsProvider,
                                TlsContextPkcs11Options tlsPkcsOptions) {
                        this.clientId = clientId;
                        this.signature = signature;
                        this.pkcsProvider = pkcsProvider;
                        this.tlsPkcsOptions = tlsPkcsOptions;
                }

                @SuppressWarnings("PMD.AvoidCatchingGenericException")
                void close() {
                        if (tlsPkcsOptions != null) {
                                try {
                                        tlsPkcsOptions.close();
                                } catch (Exception e) {
                                        logger.atWarn().setCause(e).log("Exception while closing PKCS11 TLS options");
                                }
                        }
                        if (pkcsProvider != null) {
                                closeQuietly(pkcsProvider);
                        }
                }
        }

        /** Plugin version from plugin-version.properties, filled in by Maven resource filtering. */
        private static String pluginVersion() {
                Properties props = new Properties();
                try (InputStream in = FleetProvisioningByClaimPlugin.class.getResourceAsStream("/plugin-version.properties")) {
                        if (in != null) {
                                props.load(in);
                        }
                } catch (IOException e) {
                        logger.atWarn().setCause(e).log("Could not read plugin-version.properties");
                }
                return props.getProperty("version", "unknown");
        }

        private static TlsContextOptions getTlsContextOptions(String rootCaPath) {
                return Utils.isNotEmpty(rootCaPath)
                        ? TlsContextOptions.createDefaultClient().withCertificateAuthorityFromPath(null, rootCaPath)
                        : TlsContextOptions.createDefaultClient();
        }

        private void validateParameters(Map<String, Object> parameterMap) {
                logger.atDebug().kv("parameters", parameterMap.toString()).log("The parameter map for plugin is ");
                List<String> errors = new ArrayList<>();
                checkRequiredParameterPresent(parameterMap, errors, PROVISION_ENDPOINT_PARAMETER_NAME);
                checkRequiredParameterPresent(parameterMap, errors, PROVISIONING_TEMPLATE_PARAMETER_NAME);
                checkRequiredParameterPresent(parameterMap, errors, CLAIM_CERTIFICATE_PATH_PARAMETER_NAME);
                checkRequiredParameterPresent(parameterMap, errors, CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME);
                checkRequiredParameterPresent(parameterMap, errors, SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME);
                checkRequiredParameterPresent(parameterMap, errors, ROOT_CA_PATH_PARAMETER_NAME);
                checkRequiredParameterPresent(parameterMap, errors, ROOT_PATH_PARAMETER_NAME);

                if (!errors.isEmpty()) {
                        throw new RuntimeException(errors.toString());
                }
        }

        private ProvisionConfiguration createProvisioningConfiguration(Map<String, Object> parameterMap,
                        String iotDataEndpoint,
                        String iotCredentialEndpoint,
                        RegisterThingResponse registerThingResponse) {

                // Nucleus configuration
                NucleusConfiguration nucleusConfiguration = NucleusConfiguration.builder()
                                .iotDataEndpoint(iotDataEndpoint)
                                .build();

                nucleusConfiguration.setIotCredentialsEndpoint(iotCredentialEndpoint);

                writeDeviceConfigurationToPath(registerThingResponse,iotDataEndpoint, iotCredentialEndpoint,
                                parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString());

                // optional parameters
                Object parameterValue = parameterMap.get(AWS_REGION_PARAMETER_NAME);
                if (parameterValue != null && !Utils.isEmpty(parameterValue.toString())) {
                        nucleusConfiguration.setAwsRegion(parameterValue.toString());
                }
                parameterValue = parameterMap.get(IOT_ROLE_ALIAS_PARAMETER_NAME);
                if (parameterValue != null && !Utils.isEmpty(parameterValue.toString())) {
                        nucleusConfiguration.setIotRoleAlias(parameterValue.toString());
                }
                
                // System configuration
                String confPrivateKeyPath = null;
                String confCertPath = null;

                // If the claim certificate was a pkcs11 URI, then the we assume we've been running the pkcs11 flow
                if (parameterMap.get(CLAIM_CERTIFICATE_PATH_PARAMETER_NAME).toString().contains("pkcs11")) {
                        confPrivateKeyPath = "pkcs11:object=" + AUTH_KEY_LABEL + ";type=private";
                        confCertPath = "pkcs11:object=" + AUTH_KEY_LABEL + ";type=cert";
                } else {
                        confPrivateKeyPath = parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString()
                                                + PRIVATE_KEY_PATH_RELATIVE_TO_ROOT;
                        confCertPath = parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString()
                                                + DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT;
                }

                SystemConfiguration systemConfiguration = SystemConfiguration.builder()
                                .thingName(registerThingResponse.thingName)
                                .privateKeyPath(confPrivateKeyPath)
                                .certificateFilePath(confCertPath)
                                .rootCAPath(parameterMap.get(ROOT_CA_PATH_PARAMETER_NAME).toString())
                                .build();
                

                return ProvisionConfiguration.builder()
                                .systemConfiguration(systemConfiguration)
                                .nucleusConfiguration(nucleusConfiguration)
                                .build();
        }

        private void checkRequiredParameterPresent(Map<String, Object> parameterMap, List<String> errors,
                        String parameterName) {
                if (!parameterMap.containsKey(parameterName)
                                || parameterMap.get(parameterName) == null
                                || Utils.isEmpty(parameterMap.get(parameterName).toString())) {
                        errors.add(String.format(MISSING_REQUIRED_PARAMETERS_ERROR_FORMAT,
                                        parameterName));
                }
        }

        private void writeDeviceConfigurationToPath(RegisterThingResponse response, String iotDataEndpoint, 
                                                        String iotCredEndpoint, String rootPath) {
            try {
                // Write environment file only
                StringBuilder envContent = new StringBuilder();
                for (Map.Entry<String, String> entry : response.deviceConfiguration.entrySet()) {
                    String envVarName = camelCaseToUpperSnakeCase(entry.getKey());
                    envContent.append(envVarName)
                             .append("=")
                             .append(entry.getValue())
                             .append("\n");
                }
      
                Path envPath = Paths.get(rootPath, "/config/environment");
                if (Files.notExists(envPath)) {
                    Files.createDirectories(envPath.getParent());
                    Files.createFile(envPath);
                }
                Files.write(envPath, envContent.toString().getBytes(StandardCharsets.UTF_8));
                Platform.getInstance().setPermissions(
                    FileSystemPermission.builder().ownerRead(true).groupRead(true).build(), envPath);
      
                logger.atInfo().log("Wrote device environment configuration to {}", envPath);
      
            } catch (IOException e) {
                logger.atError().log("Caught exception while writing device configuration to file");
                throw new DeviceProvisioningRuntimeException("Failed to write device configuration", e);
            }
        }
      
        private String camelCaseToUpperSnakeCase(String camelCase) {
            return camelCase.replaceAll("([a-z])([A-Z])", "$1_$2").toUpperCase();
        }

        private void writeCertificateAndKeyToPath(CreateKeysAndCertificateResponse response, String rootPath) {
                try {
                        Path certPath = Paths.get(rootPath, DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(certPath)) {
                                Files.createDirectories(certPath.getParent());
                                Files.createFile(certPath);
                        }
                        Files.write(certPath, response.certificatePem.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(
                            FileSystemPermission.builder().ownerRead(true).ownerWrite(true).build(), certPath);

                        Path keyPath = Paths.get(rootPath, PRIVATE_KEY_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(keyPath)) {
                                Files.createDirectories(keyPath.getParent());
                                Files.createFile(keyPath);
                        }
                        Files.write(keyPath, response.privateKey.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(
                            FileSystemPermission.builder().ownerRead(true).ownerWrite(true).build(), keyPath);
                } catch (IOException e) {
                        logger.atError().log("Caught exception while writing certificate and private key to file");
                        throw new DeviceProvisioningRuntimeException("Failed to write certificate and private key", e);
                }
        }

}

