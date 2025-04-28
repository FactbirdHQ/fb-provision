package com.aws.greengrass.pkcs;

import software.amazon.awssdk.crt.io.Pkcs11Lib;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


public class PkcsProvider {
    private KeyStore keyStore;
    private String libraryPath = "/usr/lib/pkcs11/libtpm2_pkcs11.so"; // Default PKCS#11 library path
    private String password = "myuserpin"; // Default pin/password
    private String slotIndex = "1"; // Default slot index
    private Pkcs11Lib pkcs11Lib;
    
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
        // Create the SunPKCS11 configuration
        String config = String.format(
            "name=pkcs11\nlibrary=%s\nslot=%s\n",
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
    }
    
    private void loadKeyStore() {
        try {
            keyStore = KeyStore.getInstance("PKCS11");
            keyStore.load(null, password.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException("Failed to load keystore", e);
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

    public Certificate[] getCertificateChain(String alias) {
        try {
            return keyStore.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get certificate chain", e);
        }
    }
}