package in.neuw.aws.rolesanywhere.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class KeyPairGeneratorUtilV2 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateKeyPair(String algorithm, Object strength) throws Exception {
        KeyPairGenerator keyPairGenerator;

        if ("RSA".equalsIgnoreCase(algorithm)) {
            int keySize = (Integer) strength;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(keySize, new SecureRandom());
        } else if ("EC".equalsIgnoreCase(algorithm)) {
            String curveName = (String) strength;
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(ecGenSpec, new SecureRandom());
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        return keyPairGenerator.generateKeyPair();
    }

    // PKCS#1 format methods (existing)
    public static String convertToOpenSSLFormat(PrivateKey privateKey) throws Exception {
        return convertToPKCS1Format(privateKey);
    }

    public static String convertToPKCS1Format(PrivateKey privateKey) throws Exception {
        String algorithm = privateKey.getAlgorithm();

        return switch (algorithm) {
            case "EC" -> convertECKeyToPKCS1Format(privateKey);
            case "RSA" -> convertRSAKeyToPKCS1Format(privateKey);
            default -> throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
        };
    }

    private static String convertECKeyToPKCS1Format(PrivateKey privateKey) throws Exception {
        byte[] pkcs8Encoded = privateKey.getEncoded();

        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(pkcs8Encoded))) {
            PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(asn1InputStream.readObject());
            ASN1Encodable privateKeyASN1 = pkInfo.parsePrivateKey();

            ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(privateKeyASN1);

            byte[] derEncoded = ecPrivateKey.getEncoded();
            String base64Encoded = Base64.getEncoder().encodeToString(derEncoded);

            return formatPEM(base64Encoded, "EC PRIVATE KEY");
        }
    }

    private static String convertRSAKeyToPKCS1Format(PrivateKey privateKey) throws Exception {
        byte[] pkcs8Encoded = privateKey.getEncoded();

        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(pkcs8Encoded))) {
            PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(asn1InputStream.readObject());
            ASN1Encodable privateKeyASN1 = pkInfo.parsePrivateKey();

            RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(privateKeyASN1);

            byte[] derEncoded = rsaPrivateKey.getEncoded();
            String base64Encoded = Base64.getEncoder().encodeToString(derEncoded);

            return formatPEM(base64Encoded, "RSA PRIVATE KEY");
        }
    }

    // PKCS#8 format methods (new)
    public static String convertToPKCS8Format(PrivateKey privateKey) throws Exception {
        // PKCS#8 is the default format that Java uses - privateKey.getEncoded() returns PKCS#8 DER
        byte[] pkcs8Encoded = privateKey.getEncoded();
        String base64Encoded = Base64.getEncoder().encodeToString(pkcs8Encoded);
        
        return formatPEM(base64Encoded, "PRIVATE KEY");
    }

    // Public key methods
    public static String convertPublicKeyToPEM(PublicKey publicKey) throws Exception {
        byte[] encoded = publicKey.getEncoded();
        String base64Encoded = Base64.getEncoder().encodeToString(encoded);
        
        return formatPEM(base64Encoded, "PUBLIC KEY");
    }

    private static String formatPEM(String base64Encoded, String header) {
        StringBuilder result = new StringBuilder();
        result.append("-----BEGIN ").append(header).append("-----\n");

        int lineLength = 64;
        for (int i = 0; i < base64Encoded.length(); i += lineLength) {
            int endIndex = Math.min(i + lineLength, base64Encoded.length());
            result.append(base64Encoded, i, endIndex).append("\n");
        }

        result.append("-----END ").append(header).append("-----");
        return result.toString();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== EC Key Examples (secp384r1) ===");
        KeyPair ecKeyPair = generateKeyPair("EC", "secp384r1");
        
        // PKCS#1 format (traditional OpenSSL format)
        System.out.println("EC Private Key in PKCS#1 Format:");
        String ecPKCS1Key = convertToPKCS1Format(ecKeyPair.getPrivate());
        System.out.println(ecPKCS1Key);
        
        // PKCS#8 format (unencrypted)
        System.out.println("\nEC Private Key in PKCS#8 Format:");
        String ecPKCS8Key = convertToPKCS8Format(ecKeyPair.getPrivate());
        System.out.println(ecPKCS8Key);
        
        // Public key
        System.out.println("\nEC Public Key:");
        String ecPublicKey = convertPublicKeyToPEM(ecKeyPair.getPublic());
        System.out.println(ecPublicKey);

        System.out.println("\n=== RSA Key Examples (2048-bit) ===");
        KeyPair rsaKeyPair = generateKeyPair("RSA", 2048);
        
        // PKCS#1 format (traditional OpenSSL format)
        System.out.println("RSA Private Key in PKCS#1 Format:");
        String rsaPKCS1Key = convertToPKCS1Format(rsaKeyPair.getPrivate());
        System.out.println(rsaPKCS1Key);
        
        // PKCS#8 format (unencrypted)
        System.out.println("\nRSA Private Key in PKCS#8 Format:");
        String rsaPKCS8Key = convertToPKCS8Format(rsaKeyPair.getPrivate());
        System.out.println(rsaPKCS8Key);
        
        // Public key
        System.out.println("\nRSA Public Key:");
        String rsaPublicKey = convertPublicKeyToPEM(rsaKeyPair.getPublic());
        System.out.println(rsaPublicKey);
    }
}