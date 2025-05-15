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

                        if (!useTpmProvisioning) {
                                PrivateKey privKey = this.deviceIdentityHelper.readPrivateKey(new File(signKeyPath));
                                signature = this.deviceIdentityHelper.sign(clientId, privKey);
                        } else {
                                signature = pkcsProviderInstance.sign(clientId, SIGN_KEY_LABEL);
                        }
                } catch (GeneralSecurityException | IOException ex) {
                        logger.atError().setCause(ex)
                                        .log("Exception encountered while signing the clientId");
                        throw new InterruptedException();
                }

                exitprogram();

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


                TlsContextPkcs11Options options = null;
                try {
                        String certificateContent = pkcsProviderInstance.getCertificateInPEM("claim");
                        options = new TlsContextPkcs11Options(pkcsProviderInstance.getPkcs11Lib())
                        .withSlotId(1)
                        .withUserPin("myuserpin")
                        .withPrivateKeyObjectLabel("claim")
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
                                                            .getFutureAfterCompletion(
                                                                mgmtCloudRouter.getEndpoint(clientId, signature),
                                                                "Caught exception during getting endpoint from mgmt"
                                                            );

                                                        provisionedIotDataEndpoint = getEndpointResponse.iotDataEndpoint;
                                                        provisionedIotCredentialsEndpoint = getEndpointResponse.iotCredentialsEndpoint;
                                                        logger.atInfo()
                                                            .kv("provisionedIotDataEndpoint", provisionedIotDataEndpoint)
                                                            .kv("provisionedIotCredentialsEndpoint", provisionedIotCredentialsEndpoint)
                                                            .log("Successfully obtained cloud endpoints");

                                                        // If we get this far, we've successfully gotten claimed.
                                                        success = true;
                                                } catch (Exception e) {
                                                        logger.atError()
                                                            .log("Didn't receive endpoint. Is the device claimed? Retrying in 15 minuttes.");
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

                        String certificateOwnershipToken;

                        boolean doFileflow = false;
                        if (doFileflow) {
                                // if (csrPath == null || Utils.isEmpty(csrPath)) {
                                logger.atInfo().log("Provisioning with certificates from filespaths");
                                CreateKeysAndCertificateResponse response;
                                response = FutureExceptionHandler.getFutureAfterCompletion(
                                    iotIdentityHelper.createKeysAndCertificate(),
                                    "Caught exception during PublishCreateKeysAndCertificate");

                                writeCertificateAndKeyToPath(response,
                                    parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString());
                                addCertificateAndKeyToStore(
                                    parameterMap.get(ROOT_PATH_PARAMETER_NAME).toString());
                                                                                
                                certificateOwnershipToken = response.certificateOwnershipToken;
                        } else {
                                logger.atInfo().log("Provisioning with CSR flow");
                                // String csrFilePath = parameterMap.get(CSR_PATH_PARAMETER_NAME).toString();
                                // String csrPrivateKeyPath = parameterMap.get(CSR_PRIVATE_KEY_PATH_PARAMETER_NAME).toString();
                                String csrFilePath = "/data/greengrass/csr.pem";
                                String csrPrivateKeyPath = "/data/greengrass/csr_private.pem";
                                // try {
                                //         Path csrFile = Paths.get(csrFilePath);
                                //         csr = new String(Files.readAllBytes(csrFile), StandardCharsets.UTF_8);
                                // } catch (IOException | SecurityException ex) {
                                //         logger.atError().setCause(ex).log("Caught exception while reading the CSR file");
                                //         throw new DeviceProvisioningRuntimeException(
                                //         "Failed to read CSR file: " + csrFilePath, ex);
                                // }

                                // Create keypair 
                                KeyPair authKeys = pkcsProviderInstance.generateKeyPair();

                                // Create CSR
                                String csr = pkcsProviderInstance.generateCSR("auth", authKeys);


                                CreateCertificateFromCsrResponse response;
                                response = FutureExceptionHandler.getFutureAfterCompletion(
                                    iotIdentityHelper.createCertificateFromCsr(csr),
                                    "Caught exception during PublishCreateCertificateFromCsr");

                                // write the keys and certificate to the keystore
                                pkcsProviderInstance.addCertificateToKeystore(
                                    "auth", authKeys, response.certificatePem);

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

                        pkcsProviderInstance.close();

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
                                .privateKeyPath("pkcs11:object=auth;type=private")
                                .certificateFilePath("pkcs11:object=auth;type=cert")
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
                        Platform.getInstance().setPermissions(
                            FileSystemPermission.builder().ownerRead(true).ownerWrite(true).build(), confPath);
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

        private void writeCertificate(String certificate, String rootPath) {
                try {
                        Path certPath = Paths.get(rootPath, DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT);
                        if (Files.notExists(certPath)) {
                                Files.createDirectories(certPath.getParent());
                                Files.createFile(certPath);
                        }
                        Files.write(certPath, certificate.getBytes(StandardCharsets.UTF_8));
                        Platform.getInstance().setPermissions(
                            FileSystemPermission.builder().ownerRead(true).ownerWrite(true).build(), certPath);
                        logger.atInfo().log("Successfully wrote certificate to file: " + certPath.toString());
                } catch (IOException e) {
                        logger.atError().log("Caught exception while writing certificate to file");
                        throw new DeviceProvisioningRuntimeException("Failed to write certificate", e);
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

        // Methods uses syscalls to get certificate and private key into TPM
        private void addCertificateAndKeyToStore(String rootPath) {
                //construct the paths to the certificate and private key
                String privateKeyPath = rootPath + PRIVATE_KEY_PATH_RELATIVE_TO_ROOT;
                String certificatePath = rootPath + DEVICE_CERTIFICATE_PATH_RELATIVE_TO_ROOT;

                //add the certificate and private key to the store
                try {
                        // Create the first tpm2_ptool command
                        String[] commandKey = {
                                "tpm2_ptool",
                                "import",
                                "--label", "claimtokenlabel",
                                "--userpin", "myuserpin",
                                "--privkey", privateKeyPath,
                                "--algorithm", "rsa",
                                "--key-label", "authkeylabel",
                                "--path", "/data/pkcs-store/"
                        };

                        // Execute the command
                        ProcessBuilder processBuilder = new ProcessBuilder(commandKey); 
                        processBuilder.redirectErrorStream(true); // Combine stdout and stderr
                        Process process = processBuilder.start();
                        
                        // logProcessOutput(process);  

                        // Wait for the process to complete
                        int exitCode = process.waitFor();
                        if (exitCode != 0) {
                                throw new RuntimeException("tpm2_ptool command failed with exit code: " + exitCode);
                        }

                       logger.atInfo().log("privatekey successfully added to TPM using tpm2_ptool.");
                } catch (Exception e) {
                                throw new DeviceProvisioningRuntimeException("Failed to add certificate to store", e);
                
                }
                
                try {
                        // Build the tpm2_ptool command
                        String[] commandCrt = {
                                "tpm2_ptool",
                                "addcert",
                                "--label", "claimtokenlabel",
                                "--key-label", "authkeylabel",
                                "--path", "/data/pkcs-store/",
                                certificatePath
                                };

                        // Execute the command
                        ProcessBuilder processBuilder = new ProcessBuilder(commandCrt);
                        processBuilder.redirectErrorStream(true); // Combine stdout and stderr
                        Process process = processBuilder.start();

                        // logProcessOutput(process);  

                        // Wait for the process to complete
                        int exitCode = process.waitFor();
                        if (exitCode != 0) {
                                throw new RuntimeException("tpm2_ptool command failed with exit code: " + exitCode);
                        }

                       logger.atInfo().log("Certificate successfully added to TPM using tpm2_ptool.");
                } catch (Exception e) {
                                throw new DeviceProvisioningRuntimeException("Failed to add private key to store", e);
                }

        }
        
        private void logProcessOutput(Process process) {
                StringBuilder outputBuilder = new StringBuilder();
                try (java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(process.getInputStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                        outputBuilder.append(line).append("\n");
                        }
                } catch (IOException e) {
                        logger.atError().setCause(e).log("Error while reading process output");
                }

                // Log the complete output
                if (outputBuilder.length() > 0) {
                        logger.atInfo().log("Process output: \n" + outputBuilder.toString());
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


        // Attemps at restartings the PKCS#11 provider upon successful provisioning

        // // Accessing kernel attempt 
        // private void restartPkcs11Provider() {
        //         // 1) Get the singleton Greengrass kernel
        //         Kernel kernel = Kernel.getInstance();

        //         // 2) Obtain the ComponentManager from the Dagger context
        //         ComponentManager compMgr = kernel.getContext().get(ComponentManager.class);

        //         // 3) Request a restart of the PKCS#11 provider
        //         compMgr.restartComponent("aws.greengrass.Pkcs11Provider")
        //         .whenComplete((ignored, err) -> {
        //                 if (err == null) {
        //                         System.out.println("✅ PKCS#11 provider restart requested.");
        //                 } else {
        //                         err.printStackTrace();
        //                 }
        //         });
        // }

        // //IPC CLIENT ATTEMPT
        // String authToken = System.getenv("SVCUID");
        // String socketPath = "/data/greengrass/ipc.socket";
        // if (authToken == null) {
        //         logger.atWarn().log("Environment variable for IPC authorization token is missing!");
        // } else {
        //         logger.atInfo().log("Authorization token (truncated): " + authToken.substring(0, Math.min(authToken.length(), 10)) + "...");
        // }

        // // Testing the ability to restart PkcsProvider
        // logger.atInfo().log("Restarting PKCS#11 provider");
        // try {
        //         // Add your code here
        //         logger.atInfo().log("Creating IPC client");
        //         GreengrassCoreIPCClientV2 ipcClient = GreengrassCoreIPCClientV2.builder()
        //                 .withSocketPath(socketPath)
        //                 .build();

        //         // 1) Build the restart request targeting your PKCS#11 provider
        //         logger.atInfo().log("Building restart request");
        //         RestartComponentRequest request = new RestartComponentRequest()
        //                 .withComponentName("aws.greengrass.Pkcs11Provider");

        //         logger.atInfo().log("Getting response");
        //         RestartComponentResponse resp = ipcClient.restartComponent(request);

        //          if ("SUCCEEDED".equals(resp.getRestartStatusAsString())) {
        //                 logger.atInfo().log("✅ PKCS#11 provider restarted successfully");
        //         } else {
        //                 logger.atInfo().log("❌ Restart failed: " + resp.getMessage());
        //         }
        // } catch (Exception e) {
        //         logger.atError().setCause(e).log("An error occurred");
        // }