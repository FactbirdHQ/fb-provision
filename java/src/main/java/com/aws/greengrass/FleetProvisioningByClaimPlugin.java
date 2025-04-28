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
import software.amazon.awssdk.iot.iotidentity.model.CreateKeysAndCertificateResponse;
import software.amazon.awssdk.iot.iotidentity.model.RegisterThingResponse;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
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

        @Override
        public ProvisionConfiguration updateIdentityConfiguration(ProvisionContext provisionContext)
                        throws RetryableProvisioningException, InterruptedException {

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
                try {
                        clientId = this.deviceIdentityHelper.getClientId();
                        PrivateKey privKey = this.deviceIdentityHelper.readPrivateKey(new File(signKeyPath));
                        signature = this.deviceIdentityHelper.sign(clientId, privKey);
                        logger.atInfo().kv("clientId", clientId)
                                                 .kv("signature", signature)
                                                 .log("Generated device signature");
                } catch (GeneralSecurityException | IOException ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while getting claimed cloud endpoint information");
                        throw new InterruptedException();
                }

                MqttConnectionParametersBuilder mqttParameterBuilder = MqttConnectionHelper.MqttConnectionParameters
                                .builder()
                                .certificateUri(certPath)
                                .privKeyUri(keyPath)
                                .rootCaPath(rootCaPath)
                                .clientId(clientId)
                                .httpProxyOptions(httpProxyOptions)
                                .mqttPort(mqttPort);

                String provisionedIotDataEndpoint = "";
                String provisionedIotCredentialsEndpoint = "";

                // Initialize PKCS11 provider
                PkcsProvider pkcsProviderInstance = new PkcsProvider();

                TlsContextPkcs11Options options = null;
                try {
                        String certificateContent = pkcsProviderInstance.getCertificateInPEM("claimkeylabel");
                        options = new TlsContextPkcs11Options(pkcsProviderInstance.getPkcs11Lib())
                        .withSlotId(1)
                        .withUserPin("myuserpin")
                        .withPrivateKeyObjectLabel("claimkeylabel")
                        .withCertificateFileContents(certificateContent); 
                } catch (Exception e) {
                        throw new RuntimeException("Failed to initialize PKCS11 provider", e);
                }

                // Obtain cloud endpoint
                try (EventLoopGroup eventLoopGroup = new EventLoopGroup(1);
                                HostResolver resolver = new HostResolver(eventLoopGroup);
                                ClientBootstrap clientBootstrap = new ClientBootstrap(eventLoopGroup, resolver);

                                // Connect
                                MqttClientConnection mgmtConnection = mqttConnectionHelper
                                                .getMqttConnectionPkcs(mqttParameterBuilder
                                                                .endpoint(provisionEndpoint)
                                                                .clientBootstrap(clientBootstrap).build(), options)) {

                                        CompletableFuture<Boolean> connected = mgmtConnection.connect();
                                        FutureExceptionHandler.getFutureAfterCompletion(connected,
                                                        "Caught exception while establishing connection to AWS Iot");

                                        boolean success = false;
                                        while (!success) {
                                                try {
                                                        MgmtCloudRouter mgmtCloudRouter = mgmtCloudRouterFactory.getInstance(mgmtConnection);

                                                        GetEndpointResponse getEndpointResponse = FutureExceptionHandler
                                                                        .getFutureAfterCompletion(mgmtCloudRouter.getEndpoint(clientId, signature),
                                                                                        "Caught exception during getting endpoint from mgmt");

                                                        provisionedIotDataEndpoint = getEndpointResponse.iotDataEndpoint;
                                                        provisionedIotCredentialsEndpoint = getEndpointResponse.iotCredentialsEndpoint;
                                                        logger.atInfo().kv("provisionedIotDataEndpoint", provisionedIotDataEndpoint)
                                                                                .kv("provisionedIotCredentialsEndpoint", provisionedIotCredentialsEndpoint)
                                                                                .log("Successfully obtained cloud endpoints");

                                                        // If we get this far, we've successfully gotten claimed.
                                                        success = true;
                                                } catch (Exception e) {
                                                        logger.atError().log("Didn't receive endpoint. Is the device claimed? Retrying in 15 minuttes.");
                                                        TimeUnit.MINUTES.sleep(15);
                                                }
                                                
                                        }
                                        
                                        // disconnect
                                        CompletableFuture<Void> disconnected = mgmtConnection.disconnect();
                                        FutureExceptionHandler.getFutureAfterCompletion(disconnected,
                                                        "Caught exception while disconnecting");

                } catch (CrtRuntimeException | InterruptedException ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while getting claimed cloud endpoint information");
                        throw ex;
                }

                String certificateTest = pkcsProviderInstance.getCertificateInPEM("claimkeylabel"); 
                logger.atInfo().log("Successfully got certificate from PKCS11 provider:\n" + certificateTest + "\n");

                pkcsProviderInstance.writeCertificateToStore("testlabel", certificateTest);


                exitprogram();

                // Provision in obtained cloud
                try (EventLoopGroup eventLoopGroup = new EventLoopGroup(1);
                                HostResolver resolver = new HostResolver(eventLoopGroup);
                                ClientBootstrap clientBootstrap = new ClientBootstrap(eventLoopGroup, resolver);

                                MqttClientConnection connection = mqttConnectionHelper
                                                .getMqttConnectionPkcs(mqttParameterBuilder
                                                                .endpoint(provisionedIotDataEndpoint)
                                                                .clientBootstrap(clientBootstrap).build(), options)) {

                        // Setup new connection to `provisionedIotDataEndpoint`
                        CompletableFuture<Boolean> connected = connection.connect();
                        FutureExceptionHandler.getFutureAfterCompletion(connected,
                                        "Caught exception while establishing connection to AWS Iot");

                        IotIdentityHelper iotIdentityHelper = iotIdentityHelperFactory.getInstance(connection);
                        CreateKeysAndCertificateResponse response;
                        response = FutureExceptionHandler.getFutureAfterCompletion(
                                        iotIdentityHelper.createKeysAndCertificate(),
                                        "Caught exception during PublishCreateKeysAndCertificate");

                        writeCertificateAndKeyToPath(response, parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString());
                        
                        HashMap<String, String> parameterHashMap = new HashMap<>();
                        if (templateParameters != null) {
                                templateParameters.forEach((k, v) -> parameterHashMap.put(k, v.toString()));
                        }

                        // Add uuid & signature
                        parameterHashMap.put("uuid", clientId);
                        parameterHashMap.put("signature", signature);

                        Future<RegisterThingResponse> registerFuture = iotIdentityHelper
                                        .registerThing(response.certificateOwnershipToken, templateName,
                                                        parameterHashMap);
                        RegisterThingResponse registerThingResponse = FutureExceptionHandler
                                        .getFutureAfterCompletion(registerFuture,
                                                        "Caught exception during registering Iot Thing");
                        CompletableFuture<Void> disconnected = connection.disconnect();
                        FutureExceptionHandler.getFutureAfterCompletion(disconnected,
                                        "Caught exception while disconnecting");

                        return createProvisioningConfiguration(parameterMap, provisionedIotDataEndpoint,
                                        provisionedIotCredentialsEndpoint,
                                        registerThingResponse);
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

                SystemConfiguration systemConfiguration = SystemConfiguration.builder()
                                .thingName(registerThingResponse.thingName)
                                .privateKeyPath(parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString()
                                                + PRIVATE_KEY_PATH_RELATIVE_TO_ROOT)
                                .certificateFilePath(parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString()
                                                + DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT)
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

        private void writeDeviceConfigurationToPath(RegisterThingResponse response, String iotDataEndpoint, String iotCredEndpoint, String rootPath) {
                try {
                        // Store registerThingResponse.deviceConfiguration to some file in JSON format.

                        JsonObject modifiedDeviceConfiguration = new JsonObject();
                        modifiedDeviceConfiguration.addProperty("iotDataEndpoint", iotDataEndpoint);
                        modifiedDeviceConfiguration.addProperty("iotCredEndpoint", iotCredEndpoint);

                        for (Map.Entry<String, String> entry : response.deviceConfiguration.entrySet()) {
                                modifiedDeviceConfiguration.addProperty(entry.getKey(), entry.getValue());
                        }

                        String jsonData = modifiedDeviceConfiguration.toString();

                        Path confPath = Paths.get(rootPath, DEVICE_CONFIGURATION_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(confPath)) {
                                Files.createDirectories(confPath.getParent());
                                Files.createFile(confPath);
                        }
                        Files.write(confPath, jsonData.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(FileSystemPermission.builder().ownerRead(true)
                                        .ownerWrite(true).build(), confPath);
                } catch (IOException e) {
                        logger.atError().log("Caught exception while writing device configuration to file");
                        throw new DeviceProvisioningRuntimeException("Failed to write device configuration", e);
                }

        }

        private void writeCertificateAndKeyToPath(CreateKeysAndCertificateResponse response, String rootPath) {
                try {
                        Path certPath = Paths.get(rootPath, DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(certPath)) {
                                Files.createDirectories(certPath.getParent());
                                Files.createFile(certPath);
                        }
                        Files.write(certPath, response.certificatePem.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(FileSystemPermission.builder().ownerRead(true)
                                        .ownerWrite(true).build(), certPath);

                        Path keyPath = Paths.get(rootPath, PRIVATE_KEY_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(keyPath)) {
                                Files.createDirectories(keyPath.getParent());
                                Files.createFile(keyPath);
                        }
                        Files.write(keyPath, response.privateKey.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(FileSystemPermission.builder().ownerRead(true)
                                        .ownerWrite(true).build(), keyPath);
                } catch (IOException e) {
                        logger.atError().log("Caught exception while writing certificate and private key to file");
                        throw new DeviceProvisioningRuntimeException("Failed to write certificate and private key", e);
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

