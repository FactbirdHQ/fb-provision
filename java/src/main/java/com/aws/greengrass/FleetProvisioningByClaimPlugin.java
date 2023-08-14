/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass;

import com.aws.greengrass.MqttConnectionHelper.MqttConnectionParameters.MqttConnectionParametersBuilder;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.model.GetEndpointResponse;
import com.aws.greengrass.provisioning.DeviceIdentityInterface;
import com.aws.greengrass.provisioning.ProvisionConfiguration;
import com.aws.greengrass.provisioning.ProvisionConfiguration.NucleusConfiguration;
import com.aws.greengrass.provisioning.ProvisionConfiguration.SystemConfiguration;
import com.aws.greengrass.provisioning.ProvisionContext;
import com.aws.greengrass.provisioning.exceptions.RetryableProvisioningException;
import com.aws.greengrass.util.FileSystemPermission;
import com.aws.greengrass.util.Utils;
import com.aws.greengrass.util.platforms.Platform;
import software.amazon.awssdk.crt.CrtRuntimeException;
import software.amazon.awssdk.crt.http.HttpProxyOptions;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.EventLoopGroup;
import software.amazon.awssdk.crt.io.HostResolver;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.iot.iotidentity.model.CreateKeysAndCertificateResponse;
import software.amazon.awssdk.iot.iotidentity.model.RegisterThingResponse;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

public class FleetProvisioningByClaimPlugin implements DeviceIdentityInterface {

        static final String PLUGIN_NAME = "aws.greengrass.FleetProvisioningByClaim";
        private static final Logger logger = LogManager.getLogger(FleetProvisioningByClaimPlugin.class);

        // Required parameters
        static final String PROVISION_ENDPOINT = "provisionEndpoint";
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

        static final String DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT = "/auth/prov.cert.pem";
        static final String PRIVATE_KEY_PATH_RELATIVE_TO_ROOT = "/auth/prov.pkey.pem";

        private final IotIdentityHelperFactory iotIdentityHelperFactory;
        private final MgmtCloudRouterFactory mgmtCloudRouterFactory;
        private final MqttConnectionHelper mqttConnectionHelper;

        public FleetProvisioningByClaimPlugin() {
                iotIdentityHelperFactory = new IotIdentityHelperFactory();
                mgmtCloudRouterFactory = new MgmtCloudRouterFactory();
                mqttConnectionHelper = new MqttConnectionHelper();
        }

        FleetProvisioningByClaimPlugin(IotIdentityHelperFactory iotIdentityHelperFactory,
                        MgmtCloudRouterFactory mgmtCloudRouterFactory,
                        MqttConnectionHelper mqttConnectionHelper) {
                this.iotIdentityHelperFactory = iotIdentityHelperFactory;
                this.mgmtCloudRouterFactory = mgmtCloudRouterFactory;
                this.mqttConnectionHelper = mqttConnectionHelper;
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
                String provisionEndpoint = parameterMap.get(PROVISION_ENDPOINT).toString();
                String rootCaPath = parameterMap.get(ROOT_CA_PATH_PARAMETER_NAME).toString();
                String templateName = parameterMap.get(PROVISIONING_TEMPLATE_PARAMETER_NAME).toString();
                String proxyUrl = parameterMap.get(PROXY_URL_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PROXY_URL_PARAMETER_NAME).toString();
                String proxyUserName = parameterMap.get(PROXY_USERNAME_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PROXY_USERNAME_PARAMETER_NAME).toString();
                String proxyPassword = parameterMap.get(PROXY_PASSWORD_PARAMETER_NAME) == null ? null
                                : parameterMap.get(PROXY_PASSWORD_PARAMETER_NAME).toString();
                HttpProxyOptions httpProxyOptions = MqttConnectionHelper.getHttpProxyOptions(proxyUrl, proxyUserName,
                                proxyPassword);
                Map<String, Object> templateParameters = (Map<String, Object>) parameterMap
                                .get(TEMPLATE_PARAMETERS_PARAMETER_NAME);

                String signature = "";
                String clientId = "";
                try {
                        clientId = getClientId();
                        PrivateKey privKey = readPrivateKey(new File(signKeyPath));
                        signature = sign(clientId, privKey);
                } catch (Exception ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while getting claimed cloud endpoint information");
                        throw new InterruptedException();
                }

                MqttConnectionParametersBuilder mqttParameterBuilder = MqttConnectionHelper.MqttConnectionParameters
                                .builder()
                                .certPath(certPath)
                                .keyPath(keyPath)
                                .rootCaPath(rootCaPath)
                                .clientId(clientId)
                                .httpProxyOptions(httpProxyOptions)
                                .mqttPort(mqttPort);

                String provisionedIotDataEndpoint = "";
                String provisionedIotCredentialsEndpoint = "";

                // Obtain cloud endpoint
                try (EventLoopGroup eventLoopGroup = new EventLoopGroup(1);
                                HostResolver resolver = new HostResolver(eventLoopGroup);
                                ClientBootstrap clientBootstrap = new ClientBootstrap(eventLoopGroup, resolver);

                                MqttClientConnection mgmtConnection = mqttConnectionHelper
                                                .getMqttConnection(mqttParameterBuilder
                                                                .endpoint(provisionEndpoint)
                                                                .clientBootstrap(clientBootstrap).build())) {

                        CompletableFuture<Boolean> connected = mgmtConnection.connect();
                        FutureExceptionHandler.getFutureAfterCompletion(connected,
                                        "Caught exception while establishing connection to AWS Iot");

                        MgmtCloudRouter mgmtCloudRouter = mgmtCloudRouterFactory.getInstance(mgmtConnection);

                        GetEndpointResponse getEndpointResponse = FutureExceptionHandler
                                        .getFutureAfterCompletion(mgmtCloudRouter.getEndpoint(clientId, signature),
                                                        "Caught exception during getting endpoint from mgmt");

                        provisionedIotDataEndpoint = getEndpointResponse.iotDataEndpoint;
                        provisionedIotCredentialsEndpoint = getEndpointResponse.iotCredentialsEndpoint;

                        // disconnect
                        CompletableFuture<Void> disconnected = mgmtConnection.disconnect();
                        FutureExceptionHandler.getFutureAfterCompletion(disconnected,
                                        "Caught exception while disconnecting");
                } catch (CrtRuntimeException | InterruptedException ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while getting claimed cloud endpoint information");
                        throw ex;
                }

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

        private void validateParameters(Map<String, Object> parameterMap) {
                logger.atDebug().kv("parameters", parameterMap.toString()).log("The parameter map for plugin is ");
                List<String> errors = new ArrayList<>();
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

        private static String getClientId() {
                String result = null;
                String[] cmd  = {"uuid"};
                try (InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();
                        Scanner s = new Scanner(inputStream).useDelimiter("\\A")) {
                    result = s.hasNext() ? s.next() : null;
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return result;
        }

        private RSAPrivateKey readPrivateKey(File file) throws Exception {
                String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

                String privateKeyPEM = key
                                .replace("-----BEGIN PRIVATE KEY-----", "")
                                .replaceAll(System.lineSeparator(), "")
                                .replace("-----END PRIVATE KEY-----", "");

                byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
                return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }

        private static String sign(String plainText, PrivateKey privateKey) throws Exception {
                Signature privateSignature = Signature.getInstance("SHA256withRSA");
                privateSignature.initSign(privateKey);
                privateSignature.update(plainText.getBytes("UTF8"));

                byte[] signature = privateSignature.sign();

                return Base64.getEncoder().encodeToString(signature);
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

        private void writeCertificateAndKeyToPath(CreateKeysAndCertificateResponse response, String rootPath) {
                try {
                        Path certPath = Paths.get(rootPath, DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(certPath)) {
                                Files.createFile(certPath);
                        }
                        Files.write(certPath, response.certificatePem.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(FileSystemPermission.builder().ownerRead(true).build(),
                                        certPath);

                        Path keyPath = Paths.get(rootPath, PRIVATE_KEY_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(keyPath)) {
                                Files.createFile(keyPath);
                        }
                        Files.write(keyPath, response.privateKey.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(FileSystemPermission.builder().ownerRead(true).build(),
                                        keyPath);
                } catch (IOException e) {
                        logger.atError().log("Caught exception while writing certificate and private key to file");
                        throw new RuntimeException(e);
                }
        }
}
