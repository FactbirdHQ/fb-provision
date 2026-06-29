/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Modifications Copyright 2022-2026 Factbird ApS. All Rights Reserved.
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
import software.amazon.awssdk.crt.CrtRuntimeException;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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

        static String SIGN_KEY_LABEL = null;
        static String CLAIM_KEY_LABEL = null;
        static final String AUTH_KEY_LABEL = "auth";

        private final IotIdentityHelperFactory iotIdentityHelperFactory;
        private final MgmtCloudRouterFactory mgmtCloudRouterFactory;
        private final MqttConnectionHelper mqttConnectionHelper;
        private final DeviceIdentityHelper deviceIdentityHelper;

        /** Run AWS Fleet provisioning by claim flow.
         * 
         */
        public FleetProvisioningByClaimPlugin() {
                iotIdentityHelperFactory = new IotIdentityHelperFactory();
                mgmtCloudRouterFactory = new MgmtCloudRouterFactory();
                mqttConnectionHelper = new MqttConnectionHelper();
                deviceIdentityHelper = new DeviceIdentityHelper();
        }

        FleetProvisioningByClaimPlugin(IotIdentityHelperFactory iotIdentityHelperFactory,
                        MgmtCloudRouterFactory mgmtCloudRouterFactory,
                        MqttConnectionHelper mqttConnectionHelper,
                        DeviceIdentityHelper deviceIdentityHelper) {
                this.iotIdentityHelperFactory = iotIdentityHelperFactory;
                this.mgmtCloudRouterFactory = mgmtCloudRouterFactory;
                this.mqttConnectionHelper = mqttConnectionHelper;
                this.deviceIdentityHelper = deviceIdentityHelper;
        }

        @Override
        public String name() {
                return PLUGIN_NAME;
        }

        @SuppressWarnings("null")
        @Override
        public ProvisionConfiguration updateIdentityConfiguration(ProvisionContext provisionContext)
                        throws RetryableProvisioningException, InterruptedException {

                logger.atInfo().log("Running updated FleetProvisioningByClaimPlugin with DNS retry logic");

                Map<String, Object> parameterMap = provisionContext.getParameterMap();
                validateParameters(parameterMap);

                String certPath = parameterMap.get(CLAIM_CERTIFICATE_PATH_PARAMETER_NAME).toString();
                String keyPath = parameterMap.get(CLAIM_CERTIFICATE_PRIVATE_KEY_PATH_PARAMETER_NAME).toString();
                String signKeyPath = parameterMap.get(SIGN_PRIVATE_KEY_PATH_PARAMETER_NAME).toString();
                Integer mqttPort = null;
                if (parameterMap.get(MQTT_PORT_PARAMETER_NAME) != null) {
                        mqttPort = Integer.valueOf(parameterMap.get(MQTT_PORT_PARAMETER_NAME).toString());
                }
                String provisionEndpoint = parameterMap.get(PROVISION_ENDPOINT_PARAMETER_NAME).toString();
                boolean useTpmProvisioning = false;
                if (parameterMap.get(USE_TPM_PROV_PARAMETER_NAME) != null) {
                        Object value = parameterMap.get(USE_TPM_PROV_PARAMETER_NAME);
                        if (value instanceof Boolean) {
                                useTpmProvisioning = (Boolean) value;
                        } else {
                                useTpmProvisioning = Boolean.parseBoolean(value.toString());
                        }
                }
                String pkcs11Library = parameterMap.get(PKCS11_LIBRARY_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PKCS11_LIBRARY_PARAMETER_NAME).toString();
                String pkcs11Slot = parameterMap.get(PKCS11_SLOT_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PKCS11_SLOT_PARAMETER_NAME).toString();
                String pkcs11UserPin = parameterMap.get(PKCS11_USER_PIN_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PKCS11_USER_PIN_PARAMETER_NAME).toString();
                String rootCaPath = parameterMap.get(ROOT_CA_PATH_PARAMETER_NAME).toString();
                String templateName = parameterMap.get(PROVISIONING_TEMPLATE_PARAMETER_NAME).toString();
                String proxyUrl = parameterMap.get(PROXY_URL_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PROXY_URL_PARAMETER_NAME).toString();
                String proxyUserName = parameterMap.get(PROXY_USERNAME_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PROXY_USERNAME_PARAMETER_NAME).toString();
                String proxyPassword = parameterMap.get(PROXY_PASSWORD_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PROXY_PASSWORD_PARAMETER_NAME).toString();
                TlsContext proxyTlsContext = new ClientTlsContext(getTlsContextOptions(rootCaPath));
                HttpProxyOptions httpProxyOptions = MqttConnectionHelper.getHttpProxyOptions(proxyUrl, proxyUserName,
                                proxyPassword, proxyTlsContext);
                Map<String, Object> templateParameters = (Map<String, Object>) parameterMap
                                .get(TEMPLATE_PARAMETERS_PARAMETER_NAME);

                String signature = "";
                String clientId = "";
                PkcsProvider pkcsProviderInstance = null;

                // Initialize PKCS11 provider and extract the key labels
                if (useTpmProvisioning) {
                        pkcsProviderInstance = new PkcsProvider(pkcs11Library, pkcs11UserPin, pkcs11Slot,
                                AUTH_KEY_LABEL);       
                        SIGN_KEY_LABEL = pkcsProviderInstance.extractObjectLabel(signKeyPath);
                        CLAIM_KEY_LABEL = pkcsProviderInstance.extractObjectLabel(certPath);

                        // if either of the labels are not found, throw an exception
                        if (SIGN_KEY_LABEL == null || CLAIM_KEY_LABEL == null) {
                                throw new DeviceProvisioningRuntimeException("Failed to extract key labels from URI's");
                        }
                } 

                // Sign the clientId with the private key
                try {
                        clientId = this.deviceIdentityHelper.getClientId();

                        if (useTpmProvisioning) {
                                signature = pkcsProviderInstance.sign(clientId, SIGN_KEY_LABEL);
                        } else {
                                PrivateKey privKey = this.deviceIdentityHelper.readPrivateKey(new File(signKeyPath));
                                signature = this.deviceIdentityHelper.sign(clientId, privKey);
                        }
                } catch (GeneralSecurityException | IOException ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while signing the clientId");
                        throw new InterruptedException();
                }

                // Create the MQTT connection parameters
                MqttConnectionParametersBuilder mqttParameterBuilder = null;
                if (useTpmProvisioning) {
                        TlsContextPkcs11Options options = pkcsProviderInstance.createTlsContextPkcs11Options(CLAIM_KEY_LABEL); 
                        mqttParameterBuilder = MqttConnectionHelper.MqttConnectionParameters
                                        .builder()
                                        .certificateUri(certPath)
                                        .privKeyUri(keyPath)
                                        .rootCaPath(rootCaPath)
                                        .clientId(clientId)
                                        .tlsPkcsOptions(options)
                                        .httpProxyOptions(httpProxyOptions)
                                        .mqttPort(mqttPort);
                } else {
                        mqttParameterBuilder = MqttConnectionHelper.MqttConnectionParameters
                                        .builder()
                                        .certificateUri(certPath)
                                        .privKeyUri(keyPath)
                                        .rootCaPath(rootCaPath)
                                        .clientId(clientId)
                                        .tlsPkcsOptions(null)
                                        .httpProxyOptions(httpProxyOptions)
                                        .mqttPort(mqttPort);
                }

                String provisionedIotDataEndpoint = "";
                String provisionedIotCredentialsEndpoint = "";

                logger.atInfo().log("Starting first MQTT connection to provision endpoint: {}", provisionEndpoint);

                // Obtain cloud endpoint with retry logic for DNS resolution failures
                try (EventLoopGroup eventLoopGroup = new EventLoopGroup(1);
                                HostResolver resolver = new HostResolver(eventLoopGroup);
                                ClientBootstrap clientBootstrap = new ClientBootstrap(eventLoopGroup, resolver)) {

                        MqttClientConnection mgmtConnection = null;
                        boolean connectionEstablished = false;
                        int maxRetries = 10; // Maximum number of retries
                        int retryCount = 0;

                        while (!connectionEstablished && retryCount < maxRetries) {
                                logger.atInfo().log("Connection attempt #{} of {}", retryCount + 1, maxRetries);
                                
                                try {
                                        // Attempt to create and connect MQTT connection
                                        logger.atDebug().log("Creating MQTT connection to endpoint: {}", provisionEndpoint);
                                        mgmtConnection = mqttConnectionHelper
                                                        .getMqttConnection(mqttParameterBuilder
                                                                        .endpoint(provisionEndpoint)
                                                                        .clientBootstrap(clientBootstrap).build());

                                        logger.atDebug().log("Attempting to connect MQTT connection...");
                                        CompletableFuture<Boolean> connected = mgmtConnection.connect();
                                        FutureExceptionHandler.getFutureAfterCompletion(connected,
                                            "Caught exception while establishing connection to AWS Iot");
                                        
                                        connectionEstablished = true;
                                        logger.atInfo().log("Successfully established MQTT connection to provision endpoint on attempt #{}", retryCount + 1);

                                } catch (Exception e) {
                                        retryCount++;
                                        logger.atWarn().setCause(e)
                                                .kv("attemptNumber", retryCount)
                                                .kv("maxRetries", maxRetries)
                                                .log("MQTT connection attempt #{} failed.", retryCount);

                                        if (mgmtConnection != null) {
                                                try {
                                                        logger.atDebug().log("Cleaning up failed connection...");
                                                        mgmtConnection.close();
                                                } catch (Exception closeEx) {
                                                        logger.atWarn().setCause(closeEx).log("Exception while closing failed connection");
                                                }
                                                mgmtConnection = null;
                                        }
                                        
                                        if (retryCount < maxRetries) {
                                                logger.atWarn().setCause(e)
                                                        .kv("retryCount", retryCount)
                                                        .kv("maxRetries", maxRetries)
                                                        .log("Failed to establish MQTT connection, retrying in 20 seconds... (attempt {} of {})", retryCount, maxRetries);
                                                TimeUnit.SECONDS.sleep(20);
                                        } else {
                                                logger.atError().setCause(e)
                                                        .log("Failed to establish MQTT connection after {} retries", maxRetries);
                                                throw e;
                                        }
                                }
                        }

                        logger.atInfo().log("MQTT connection establishment. Getting claim status");

                        try {
                                boolean success = false;
                                while (!success) {
                                        try {
                                                MgmtCloudRouter mgmtCloudRouter = mgmtCloudRouterFactory.getInstance(mgmtConnection);

                                                GetEndpointResponse getEndpointResponse = FutureExceptionHandler
                                                    .getFutureAfterCompletion(
                                                        mgmtCloudRouter.getEndpoint(clientId, signature),
                                                        900,
                                                        "Caught exception during getting endpoint from mgmt"
                                                    );

                                                provisionedIotDataEndpoint = getEndpointResponse.iotDataEndpoint;
                                                provisionedIotCredentialsEndpoint = getEndpointResponse.iotCredentialsEndpoint;

                                                // If we get this far, we've successfully gotten claimed.
                                                success = true;
                                        } catch (Exception e) {
                                                logger.atError()
                                                    .log("Didn't receive endpoint. Is the device claimed? Retrying in 20 seconds.");
                                                TimeUnit.SECONDS.sleep(20);
                                        }
                                        
                                }
                                
                        } finally {
                                // disconnect
                                if (mgmtConnection != null) {
                                        CompletableFuture<Void> disconnected = mgmtConnection.disconnect();
                                        FutureExceptionHandler.getFutureAfterCompletion(disconnected,
                                            "Caught exception while disconnecting");
                                }
                        }

                } catch (CrtRuntimeException | InterruptedException ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while getting claimed cloud endpoint information");
                        throw ex;
                }

                logger.atInfo().log("Starting second MQTT connection to provisioned IoT endpoint: {}", provisionedIotDataEndpoint);

                // Provision in obtained cloud
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

                        if (useTpmProvisioning) {
                                logger.atInfo().log("Provisioning with CSR flow");

                                // Create keypair 
                                KeyPair authKeys = pkcsProviderInstance.generateKeyPair();

                                // Create CSR
                                String csr = pkcsProviderInstance.generateCSR(clientId, authKeys);


                                CreateCertificateFromCsrResponse response;
                                response = FutureExceptionHandler.getFutureAfterCompletion(
                                    iotIdentityHelper.createCertificateFromCsr(csr),
                                    "Caught exception during PublishCreateCertificateFromCsr");

                                // write certificate to the keystore
                                pkcsProviderInstance.addCertificateToKeystore(
                                    "auth", authKeys, response.certificatePem);

                                certificateOwnershipToken = response.certificateOwnershipToken;

                        } else {
                                logger.atInfo().log("Provisioning with certificates from filespaths");
                                CreateKeysAndCertificateResponse response;
                                response = FutureExceptionHandler.getFutureAfterCompletion(
                                    iotIdentityHelper.createKeysAndCertificate(),
                                    "Caught exception during PublishCreateKeysAndCertificate");

                                writeCertificateAndKeyToPath(response,
                                    parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString());
                                certificateOwnershipToken = response.certificateOwnershipToken;
                        }

                        HashMap<String, String> parameterHashMap = new HashMap<>();
                        if (templateParameters != null) {
                                templateParameters.forEach((k, v) -> parameterHashMap.put(k, v.toString()));
                        }
                        // Add uuid & signature
                        parameterHashMap.put("uuid", clientId);
                        parameterHashMap.put("signature", signature);

                        Future<RegisterThingResponse> registerFuture = iotIdentityHelper
                            .registerThing(certificateOwnershipToken, templateName, parameterHashMap);
                        RegisterThingResponse registerThingResponse = FutureExceptionHandler
                            .getFutureAfterCompletion(registerFuture,
                                "Caught exception during registering Iot Thing");
                        CompletableFuture<Void> disconnected = connection.disconnect();
                        FutureExceptionHandler.getFutureAfterCompletion(disconnected,
                            "Caught exception while disconnecting");

                        if (pkcsProviderInstance != null) {
                                pkcsProviderInstance.close();
                        }

                        return createProvisioningConfiguration(parameterMap, provisionedIotDataEndpoint,
                            provisionedIotCredentialsEndpoint, registerThingResponse);
                } catch (CrtRuntimeException | InterruptedException ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while getting device identity information");
                        throw ex;
                }
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

        private static void copyFile(String srcPath, String dstPath) {
                // Convert files from String to Path
                Path src = Paths.get(srcPath);
                Path dst = Paths.get(dstPath);
                try {
                        createFile(dst);
                        Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                logger.atError().kv("src", src).kv("dst", dst)
                    .log("Caught exception while copying file");
                throw new DeviceProvisioningRuntimeException(
                        String.format("Failed to copy %s to %s", src, dst), e);
                }
        }

        private static void createFile(Path file) throws IOException {

                Path parent = file.getParent();
                if (parent != null) {
                        Files.createDirectories(parent);
                }
                if (Files.notExists(file)) {
                        Files.createFile(file);
                }
        }

        private void exitprogram() throws InterruptedException {
                // log end of execution and throw a interrupted exception to exit the program
                boolean logendofexecution = true;
                if (logendofexecution) {
                        throw new InterruptedException("succesfully failed. exiting the program\n\n\n\n\n");
                }
        }
}

