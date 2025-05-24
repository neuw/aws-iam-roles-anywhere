package in.neuw.aws.rolesanywhere.utils;

import in.neuw.aws.rolesanywhere.credentials.models.X509CertificateChain;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import software.amazon.awssdk.utils.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Slf4j
public class CertAndKeyParserAndLoader {

    private CertAndKeyParserAndLoader() {}

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    // public static final String END_CERT = "-----END CERTIFICATE-----"; // not needed!
    public static final String EC_OID = "1.2.840.10045.2.1";
    public static final String RSA_OID = "1.2.840.113549.1.1.1";
    public static final String EC = "EC";
    public static final String RSA = "RSA";
    public static final String SHA256_RSA = "SHA256withRSA";
    public static final String SHA256_EC_DSA = "SHA256withECDSA";

    public static X509Certificate extractCertificate(final String base64EncodedCert){
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] decodedCertificate = Base64.getDecoder().decode(base64EncodedCert);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCertificate));
            log.info("Certificate expires at {}", cert.getNotAfter());
            return cert;
        } catch (CertificateException e) {
            log.error("Error while extracting certificate, {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static List<X509Certificate> extractCertificates(final String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        var inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(base64EncodedCert));

        List<X509Certificate> certificates = new ArrayList<>();
        for (Object cert : cf.generateCertificates(inputStream)) {
            certificates.add((X509Certificate) cert);
        }

        return certificates;
    }

    public static boolean possibleChainOfCerts(final String base64EncodedCert) {
        String rawCertFile = new String(Base64.getDecoder().decode(base64EncodedCert));
        if (countOccurrencesOfBEGINCERT(rawCertFile) == 1) {
            log.info("only one cert provided");
        } else if (countOccurrencesOfBEGINCERT(rawCertFile) > 1) {
            log.info("possible chain of certificates");
            return true;
        } else {
            log.error("cert not provided correctly");
            throw new RuntimeException("cert not provided correctly");
        }
        return false;
    }

    public static X509CertificateChain resolveCertificateChain(final String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        X509CertificateChain x509CertificateChain = new X509CertificateChain();
        x509CertificateChain.setBase64EncodedCertificate(base64EncodedCert);
        if (possibleChainOfCerts(base64EncodedCert)) {
            var certs = extractCertificates(base64EncodedCert);
            for (var cert : certs) {
                // root CA is different from intermediate CA
                if(isRootCA(cert)) {
                    log.info("root CA expires at, {}", cert.getNotAfter());
                    x509CertificateChain.setRootCACertificate(cert);
                } else if (ifX509CertIsCA(cert)){ // for intermediate CA
                    log.info("intermediate CA expires at, {}", cert.getNotAfter());
                    x509CertificateChain.setIntermediateCACertificate(cert);
                } else {
                    log.info("leaf cert expires at, {}", cert.getNotAfter());
                    x509CertificateChain.setLeafCertificate(cert); // leaf certificate
                }
            }
        } else {
            x509CertificateChain.setLeafCertificate(extractCertificate(base64EncodedCert));
        }
        return x509CertificateChain;
    }

    public static String convertToBase64PEMString(X509Certificate x509Cert) {
        Security.addProvider(new BouncyCastleProvider());
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(x509Cert);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encodeToString(sw.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static final PrivateKey extractPrivateKey(final String base64EncodedPrivateKey) {
        byte[] privateKeyBytes = Base64.getDecoder().decode(base64EncodedPrivateKey);
        try {
            return privateKeyResolver(privateKeyBytes);
        } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static String resolveSignatureAlgorithm(final PrivateKey key) {
        if (RSA.equals(key.getAlgorithm())) {
            return SHA256_RSA;
        } else if (EC.equals(key.getAlgorithm())) {
           return SHA256_EC_DSA;
        } else {
            throw new IllegalArgumentException("key algorithm not recognized");
        }
    }

    public static String resolveAndValidateAlgorithm(final PrivateKey key) {
        if (EC.equals(key.getAlgorithm()) || RSA.equals(key.getAlgorithm())) {
            return key.getAlgorithm();
        } else {
            throw new IllegalArgumentException("key algorithm not recognized");
        }
    }

    public static String resolveKeyType(ASN1ObjectIdentifier algorithm) {
        String keyType;
        if (algorithm.equals(new ASN1ObjectIdentifier(RSA_OID))) {
            log.info("The key is an RSA private key.");
            keyType = RSA;
        } else if (algorithm.equals(new ASN1ObjectIdentifier(EC_OID))) {
            log.info("The key is an EC private key.");
            keyType = EC;
        } else {
            throw new RuntimeException("Unsupported key algorithm: " + algorithm);
        }
        return keyType;
    }

    public static PrivateKey privateKeyResolver(final byte[] key) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(key);

        PEMParser pemParser = new PEMParser(new InputStreamReader(byteArrayInputStream));
        PEMKeyPair keyPair = (PEMKeyPair) pemParser.readObject();
        PrivateKeyInfo privateKeyInfo = keyPair.getPrivateKeyInfo();
        byte[] encodedKey = privateKeyInfo.getEncoded();

        ASN1ObjectIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance(resolveKeyType(algorithm), "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        log.info("Private key algorithm is : {}", privateKey.getAlgorithm());
        log.info("Private key format is : {}", privateKey.getFormat());

        log.info("Private key successfully loaded.");
        return privateKey;
    }

    public static boolean ifX509CertIsCA(final X509Certificate cert) {
        return cert.getBasicConstraints()!=-1 && cert.getKeyUsage()[5];
    }

    public static boolean isRootCA(final X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            log.info("this is root CA");
            return true;
        } catch (InvalidKeyException e) {
            log.error("this is not root CA, invalid key");
        } catch (SignatureException e) {
            log.warn("the cert with name = {} is not Root CA signature issue", cert.getSubjectX500Principal().getName());
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("this is not Root CA, exception", e.getCause());
        }
        return false;
    }

    private static int countOccurrencesOfBEGINCERT(final String str) {
        // if main string or subString is empty, makes no sense of occurrence, hence hard stopped with 0 occurrence
        if (StringUtils.isBlank(str) || StringUtils.isBlank(BEGIN_CERT)) {
            return 0;
        }

        int count = 0;
        int pos = 0;
        int idx;
        while ((idx = str.indexOf(BEGIN_CERT, pos)) != -1) {
            ++count;
            pos = idx + BEGIN_CERT.length();
        }
        return count;
    }

}
