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

public class KeyPairGeneratorUtil {

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

    public static String convertToOpenSSLFormat(PrivateKey privateKey) throws Exception {
        String algorithm = privateKey.getAlgorithm();

        switch (algorithm) {
            case "EC":
                return convertECKeyToOpenSSLFormat(privateKey);
            case "RSA":
                return convertRSAKeyToOpenSSLFormat(privateKey);
            default:
                throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
        }
    }

    private static String convertECKeyToOpenSSLFormat(PrivateKey privateKey) throws Exception {
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

    private static String convertRSAKeyToOpenSSLFormat(PrivateKey privateKey) throws Exception {
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
        // Example: EC Key with secp384r1 curve
        KeyPair ecKeyPair = generateKeyPair("EC", "secp384r1");
        String ecOpenSSLKey = convertToOpenSSLFormat(ecKeyPair.getPrivate());
        System.out.println("EC Private Key in OpenSSL Format:\n" + ecOpenSSLKey);

        // Example: RSA Key with 2048-bit size
        KeyPair rsaKeyPair = generateKeyPair("RSA", 2048);
        String rsaOpenSSLKey = convertToOpenSSLFormat(rsaKeyPair.getPrivate());
        System.out.println("\nRSA Private Key in OpenSSL Format:\n" + rsaOpenSSLKey);
    }
}
