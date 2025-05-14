package com.aws.greengrass.pkcs;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import software.amazon.awssdk.crt.io.Pkcs11Lib;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class PkcsProvider {
    private final Logger logger = LogManager.getLogger(PkcsProvider.class);
    private KeyStore keyStore;
    private String libraryPath = "/usr/lib/pkcs11/libtpm2_pkcs11.so"; // Default PKCS#11 library path
    private String password = "myuserpin"; // Default pin/password
    private String slotIndex = "1"; // Default slot index
    private Pkcs11Lib pkcs11Lib;
    private Provider pkcs11Provider;
    
    public PkcsProvider() {
        try {
            initializePKCS11();
            initializePkcs11Lib();
            loadKeyStore();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize pkcsProvider", e);
        }

    }
    
    public PkcsProvider(String libraryPath, String password, String slotIndex) {
        try {
            this.libraryPath = libraryPath;
            this.password = password;
            this.slotIndex = slotIndex;
            initializePKCS11();
            loadKeyStore();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PKCS11 keystore", e);
        }
    }
    
    
    private void initializePKCS11() throws Exception {
        // Create the SunPKCS11 configuration. NOTE: The attribute CKA_LABEL needs to be set in hex format, meaning this results in 'auth'
        String config = String.format(
            "name=pkcs11\nlibrary=%s\nslot=%s\nattributes(*,*,*) = {\n    CKA_LABEL = 0h61757468\n}\n",
            libraryPath, slotIndex
        );
        
        // Write the configuration to a file
        File configFile = new File("/data/greengrass/config/pkcs.cfg");
        // Create parent directories if they don't exist
        configFile.getParentFile().mkdirs();

        // Write configuration to the file
        java.nio.file.Files.write(
            configFile.toPath(),
            config.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        // Load the SunPKCS11 provider
        Provider provider = Security.getProvider("SunPKCS11");
        if (provider == null) {
            // If SunPKCS11 provider isn't available, this is an error
            throw new NoSuchAlgorithmException("SunPKCS11 provider not available");
        }

        // ByteArrayInputStream configStream = new ByteArrayInputStream(config.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // Configure the provider with our specific configuration
        Provider configuredProvider = provider.configure("/data/greengrass/config/pkcs.cfg");

        
        // Add the configured provider to the security providers list
        Security.addProvider(configuredProvider);

        pkcs11Provider = configuredProvider;
        if (pkcs11Provider == null) {
            throw new NoSuchAlgorithmException("Failed to load SunPKCS11 provider");
        }
    }
    
    private void loadKeyStore() {
        try {
            keyStore = KeyStore.getInstance("PKCS11");
            keyStore.load(null, password.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException("Failed to load keystore", e);
        }
    }

    public void listKeyStoreObjects() {
        try {
            logger.atInfo().log("Listing all objects in the keystore:");
            for (String alias : Collections.list(keyStore.aliases())) {
                logger.atInfo().log("Alias: " + alias);

                // Check if the alias corresponds to a private key
                if (keyStore.isKeyEntry(alias)) {
                    logger.atInfo().log("  Type: Private Key");
                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
                    if (privateKey != null) {
                        logger.atInfo().log("  Algorithm: " + privateKey.getAlgorithm());
                    }
                }

                // Check if the alias corresponds to a certificate
                if (keyStore.isCertificateEntry(alias)) {
                    logger.atInfo().log("  Type: Certificate");
                    Certificate cert = keyStore.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        X509Certificate x509Cert = (X509Certificate) cert;
                        logger.atInfo().log("  Subject: " + x509Cert.getSubjectDN());
                        logger.atInfo().log("  Issuer: " + x509Cert.getIssuerDN());
                    }
                }

                // Check if the alias corresponds to a certificate chain
                Certificate[] certChain = keyStore.getCertificateChain(alias);
                if (certChain != null) {
                    logger.atInfo().log("  Certificate Chain Length: " + certChain.length);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to list objects in the keystore", e);
        }
    }
    
    public X509Certificate getCertificate(String alias) {
        try {
            Certificate cert = keyStore.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                return (X509Certificate) cert;
            }
            return null;
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get certificate", e);
        }
    }

    
    public String getCertificateInPEM(String label) {
        try {
            X509Certificate certificate = getCertificate(label);
            if (certificate == null) {
                throw new RuntimeException("Certificate not found for label: " + label);
            }

            StringBuilder pem = new StringBuilder();
            pem.append("-----BEGIN CERTIFICATE-----\n");
            pem.append(Base64.getMimeEncoder(64, "\n".getBytes())
                    .encodeToString(certificate.getEncoded()));
            pem.append("\n-----END CERTIFICATE-----");
            return pem.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert certificate to PEM format", e);
        }
    }

    public String getPrivateKeyInPEM(String alias) {
        try {
            PrivateKey privateKey = getPrivateKey(alias);
            if (privateKey == null) {
                throw new RuntimeException("Private key not found for alias: " + alias);
            }

            // Convert the private key to PKCS#8 format
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            byte[] encodedKey = pkcs8EncodedKeySpec.getEncoded();

            // Encode the key in Base64 and format it as PEM
            StringBuilder pem = new StringBuilder();
            pem.append("-----BEGIN PRIVATE KEY-----\n");
            pem.append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encodedKey));
            pem.append("\n-----END PRIVATE KEY-----");
            return pem.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert private key to PEM format", e);
        }
    }
    
    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Failed to get private key", e);
        }
    }

    // The issue with this function can be found in ./errormessage.log
    public void writeCertificateToStore(String label, String pemCertificate) {
    try {
        if (pemCertificate == null || pemCertificate.trim().isEmpty()) {
            throw new IllegalArgumentException("PEM certificate string cannot be null or empty");
        }

        // Clean the PEM string by removing the header, footer, and any extra whitespace
        String cleanedPem = pemCertificate
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", ""); // Remove all whitespace

        if (cleanedPem.isEmpty()) {
            throw new IllegalArgumentException("PEM certificate string is invalid after cleaning");
        }

        // Decode the cleaned PEM string into bytes
        byte[] decodedBytes = Base64.getDecoder().decode(cleanedPem);

        // Parse the decoded bytes into an X509Certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream certInputStream = new ByteArrayInputStream(decodedBytes);
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);

        // Add the certificate to the keystore under the provided label
        keyStore.setCertificateEntry(label, certificate);
    } catch (Exception e) {
            throw new RuntimeException("Failed to write certificate to PKCS#11 store", e);
        }
    }

    private synchronized boolean initializePkcs11Lib() {
        closePkcs11Lib();
        try {
            pkcs11Lib = new Pkcs11Lib(libraryPath);
            return true;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize PKCS#11 library", e);
        }
    }

    private void closePkcs11Lib() {
        if (pkcs11Lib != null) {
            pkcs11Lib.close();
        }
    }
    
    public synchronized Pkcs11Lib getPkcs11Lib() {
        return pkcs11Lib;
    }

    public synchronized Provider getPkcs11Provider() {
        return pkcs11Provider;
    }

    public Certificate[] getCertificateChain(String alias) {
        try {
            return keyStore.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get certificate chain", e);
        }
    }
    
    // Attempt at signing data using the private key from TPM
    public String sign(String plainText, String label) throws GeneralSecurityException, IOException {
        try {
            // Retrieve the private key from the PKCS#11 keystore
            PrivateKey privateKey = getPrivateKey(label);
            if (privateKey == null) {
                throw new RuntimeException("Private key not found for label: " + label);
            }
            logger.atInfo().log("Signing data with private key for label: " + label); 

            // Get the configured PKCS#11 provider
            Provider provider = getPkcs11Provider();    
            if (provider == null) {
                    throw new RuntimeException("Could not find SunPKCS11 provider");
            }

            // logger.atInfo().log("Listing supported Signature algorithms by provider: %s", provider.getName());
            // for (Provider.Service service : provider.getServices()) {
            //     if ("Signature".equalsIgnoreCase(service.getType())) {
            //         logger.atInfo().log("Supported Signature:" + service.getAlgorithm());
            //     }
            // }
            
            Signature signature = Signature.getInstance("SHA256withECDSAinP1363format", provider);
            signature.initSign(privateKey);

            signature.update(plainText.getBytes("UTF-8"));

            // Perform the signing operation
            byte[] signedData = signature.sign();

            // Convert the signature to a hexadecimal string
            return new BigInteger(1, signedData).toString(16);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign data using TPM: " + e.getMessage(), e);
        }
    }

    public KeyPair generateKeyPair() throws RuntimeException{
        try {
            logger.atInfo().log("Generating key pair");

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", pkcs11Provider);
            keyPairGenerator.initialize(256); // Use 256-bit EC key
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }

   public KeyPair generateKeyPairWithLabel(String label) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", pkcs11Provider);

            // Reflectively load the Sun internal P11KeyGenParameterSpec
            Class<?> specClass =
                Class.forName("sun.security.pkcs11.P11KeyGenParameterSpec");
            Constructor<?> ctor =
                specClass.getConstructor(String.class, String.class);
            AlgorithmParameterSpec spec =
                (AlgorithmParameterSpec) ctor.newInstance(
                        "ecc256",    // curve name (prime256v1/ secp256r1)
                        label           // your CKA_LABEL
                );

            // Java 8 KeyPairGenerator has initialize(AlgorithmParameterSpec, SecureRandom)
            kpg.initialize(spec, /* SecureRandom: */ null);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate labeled EC keypair", e);
        }
    } 

    public String generateCSR(String label, KeyPair keyPair) throws RuntimeException{
        try {
            logger.atInfo().log("Generating CSR for label: " + label);

            // Step 2: Create a CSR
            String subjectDN = "CN=" + label; // Customize the subject DN as needed
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(subjectDN), keyPair.getPublic());
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
            signerBuilder.setProvider(pkcs11Provider);
            ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // Step 3: Convert the CSR to PEM format
            StringWriter pemWriter = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(pemWriter)) {
                writer.writeObject(csr);
            }

            return pemWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CSR", e);
        }
    }

    public boolean addCertificateToKeystore(String label, KeyPair keyPair, String certificatePem) {
        try {
            //parse the response.certificatePem string to the required Certificate[] chain format
            String cleanedPem = certificatePem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", ""); // Remove all whitespace

            // Decode the cleaned PEM string into bytes
            byte[] decodedBytes = Base64.getDecoder().decode(cleanedPem);

            // Parse the decoded bytes into an X509Certificate
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream certInputStream = new ByteArrayInputStream(decodedBytes);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);

            // Create a certificate chain (array) with the parsed certificate
            X509Certificate[] chain = new X509Certificate[]{certificate};

            logger.atInfo().log("Adding key to keystore with label: " + label);
            keyStore.setKeyEntry(label, keyPair.getPrivate(), password.toCharArray(), chain);
            return true;
        } catch (Exception e) {
            throw new RuntimeException("Failed to add key to keystore", e);
        }
    }


    public void close() {
        try {
            // Close the PKCS#11 library if initialized
            closePkcs11Lib();

            // Clear the KeyStore reference
            keyStore = null;

            // Optionally, remove the PKCS#11 provider from the Security list
            Provider provider = Security.getProvider("SunPKCS11");
            if (provider != null) {
                Security.removeProvider(provider.getName());
            }

            logger.atInfo().log("PkcsProvider resources have been released.");
        } catch (Exception e) {
            throw new RuntimeException("Failed to close PkcsProvider resources", e);
        }
    }

}