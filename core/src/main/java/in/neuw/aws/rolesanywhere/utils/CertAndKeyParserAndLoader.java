package in.neuw.aws.rolesanywhere.utils;

import in.neuw.aws.rolesanywhere.credentials.models.X509CertificateChain;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import software.amazon.awssdk.core.exception.SdkException;
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

/**
 * Utility class for parsing and loading X.509 certificates and private keys from Base64-encoded PEM format.
 *
 * <h2>Input Format - Critical Information</h2>
 *
 * <p><strong>All methods in this class expect a SINGLE layer of Base64 encoding applied to PEM-formatted content.</strong></p>
 *
 * <p><strong>Encoding Process:</strong></p>
 * <ol>
 *   <li>Start with a PEM file (certificate or private key) that includes headers like:
 *       <ul>
 *         <li>{@code -----BEGIN CERTIFICATE-----}</li>
 *         <li>{@code -----BEGIN PRIVATE KEY-----}</li>
 *         <li>{@code -----BEGIN RSA PRIVATE KEY-----}</li>
 *       </ul>
 *   </li>
 *   <li>Apply Base64 encoding to the <strong>entire file content</strong> (including headers and footers)</li>
 *   <li>Pass the resulting Base64 string to the methods in this class</li>
 * </ol>
 *
 * <p><strong>What this means:</strong></p>
 * <pre>
 * ✅ Correct:   Base64(entire-PEM-file) // Encode the complete PEM file including headers
 * ❌ Wrong:     Base64(raw-DER-bytes)   // Raw certificate bytes without PEM structure
 * ❌ Wrong:     Just the PEM file as-is // No Base64 encoding applied
 * </pre>
 *
 * <p><strong>Example - Certificate Encoding:</strong></p>
 * <pre>
 * Original file (cert.pem):
 * -----BEGIN CERTIFICATE-----
 * MIIDRzCCAi+gAwIBAgIQ...
 * -----END CERTIFICATE-----
 *
 * Encoding (choose one):
 * # Command line (Linux/macOS):
 * base64 -i cert.pem
 *
 * # Command line (Windows PowerShell):
 * [Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pem"))
 *
 * # Java:
 * Base64.getEncoder().encodeToString(Files.readAllBytes(Paths.get("cert.pem")))
 * </pre>
 *
 * <p><strong>Example - Private Key Encoding:</strong></p>
 * <pre>
 * Original file (key.pem):
 * -----BEGIN PRIVATE KEY-----
 * MIIEvQIBADANBgkq...
 * -----END PRIVATE KEY-----
 *
 * Encoding:
 * base64 -i key.pem
 * </pre>
 *
 * <h2>Supported Formats</h2>
 *
 * <p><strong>Certificates:</strong></p>
 * <ul>
 *   <li>Single X.509 certificates in PEM format</li>
 *   <li>Certificate chains (multiple certificates concatenated)</li>
 *   <li>Leaf certificates, intermediate CA, and root CA certificates</li>
 * </ul>
 *
 * <p><strong>Private Keys:</strong></p>
 * <ul>
 *   <li>PKCS#1 format: {@code -----BEGIN RSA PRIVATE KEY-----} or {@code -----BEGIN EC PRIVATE KEY-----}</li>
 *   <li>PKCS#8 format: {@code -----BEGIN PRIVATE KEY-----}</li>
 *   <li>RSA and EC (Elliptic Curve) algorithms</li>
 * </ul>
 *
 * <h2>Why This Encoding Strategy?</h2>
 *
 * <p>PEM files contain both:</p>
 * <ul>
 *   <li>Headers/footers that identify the content type (e.g., {@code -----BEGIN CERTIFICATE-----})</li>
 *   <li>Base64-encoded binary data (the actual certificate or key)</li>
 * </ul>
 *
 * <p>When storing PEM files in environment variables or configuration files, we need to encode
 * the entire PEM structure (headers + content) as a single Base64 string. This class then:</p>
 * <ol>
 *   <li>Decodes the Base64 string ONCE to recover the PEM format</li>
 *   <li>Uses the PEM headers to identify content type and format</li>
 *   <li>Parses the PEM content using standard Java/BouncyCastle libraries</li>
 * </ol>
 *
 * <p><strong>This is NOT double-encoding.</strong> The PEM format itself uses Base64 for the certificate/key data,
 * apply an additional (outer) Base64 encoding to make the entire PEM file safe for storage in configuration systems.</p>
 *
 * @see #extractCertificate(String)
 * @see #extractCertificates(String)
 * @see #extractPrivateKey(String)
 * @see #possibleChainOfCerts(String)
 */
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

    /**
     * Extracts a single X.509 certificate from a Base64-encoded PEM certificate.
     *
     * <p><strong>Input Format:</strong> Base64(PEM-formatted-certificate)</p>
     * <p>The input must be the result of Base64-encoding a complete PEM certificate file,
     * including the {@code -----BEGIN CERTIFICATE-----} and {@code -----END CERTIFICATE-----} headers.</p>
     *
     * <p><strong>Example encoding:</strong></p>
     * <pre>
     * # From command line:
     * base64 -i certificate.pem
     *
     * # From Java:
     * String encoded = Base64.getEncoder().encodeToString(
     *     Files.readAllBytes(Paths.get("certificate.pem"))
     * );
     * </pre>
     *
     * @param base64EncodedCert Base64-encoded PEM certificate (single encoding layer)
     * @return the parsed X.509 certificate
     * @throws SdkException if certificate parsing fails
     */
    public static X509Certificate extractCertificate(final String base64EncodedCert) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // Decode the Base64 ONCE to get the original PEM content
            byte[] decodedCertificate = Base64.getDecoder().decode(base64EncodedCert);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCertificate));
            log.info("Certificate expires at {}", cert.getNotAfter());
            return cert;
        } catch (CertificateException e) {
            log.error("Error while extracting certificate, {}", e.getMessage());
            throw SdkException.builder().message("Error while extracting certificate").cause(e).build();
        }
    }

    /**
     * Extracts one or multiple X.509 certificates from a Base64-encoded PEM certificate file/chain.
     *
     * <p><strong>Input Format:</strong> Base64(PEM-formatted-certificate-chain)</p>
     * <p>The input must be the result of Base64-encoding a PEM file containing one or more certificates,
     * each with {@code -----BEGIN CERTIFICATE-----} and {@code -----END CERTIFICATE-----} headers.</p>
     *
     * <p><strong>Example - Single certificate:</strong></p>
     * <pre>
     * Original PEM file:
     * -----BEGIN CERTIFICATE-----
     * MIIDRzCCAi+gAwIBAgIQ...
     * -----END CERTIFICATE-----
     *
     * Encoding: base64 -i certificate.pem
     * </pre>
     *
     * <p><strong>Example - Certificate chain:</strong></p>
     * <pre>
     * Original PEM file:
     * -----BEGIN CERTIFICATE-----
     * MIIDRzCCAi+gAwIBAgIQ... (Leaf)
     * -----END CERTIFICATE-----
     * -----BEGIN CERTIFICATE-----
     * MIIEADCCAuigAwIBAgIR... (Intermediate)
     * -----END CERTIFICATE-----
     * -----BEGIN CERTIFICATE-----
     * MIIDdzCCAl+gAwIBAgIJ... (Root)
     * -----END CERTIFICATE-----
     *
     * Encoding: base64 -i chain.pem
     * </pre>
     *
     * @param base64EncodedCert Base64-encoded PEM certificate or certificate chain (single encoding layer)
     * @return list of parsed X.509 certificates in the order they appear in the PEM file
     * @throws CertificateException if certificate parsing fails
     * @throws NoSuchProviderException if BouncyCastle provider is not available
     */
    public static List<X509Certificate> extractCertificates(final String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        // Decode the Base64 ONCE to get the original PEM content
        var inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(base64EncodedCert));

        List<X509Certificate> certificates = new ArrayList<>();
        for (var cert : cf.generateCertificates(inputStream)) {
            certificates.add((X509Certificate) cert);
        }

        return certificates;
    }

    /**
     * Determines if the provided certificate content contains a chain of certificates or a single certificate.
     *
     * <p><strong>IMPORTANT - Input Format:</strong></p>
     * <p>This method expects the input to be a <strong>single layer of Base64 encoding</strong> applied to a PEM-formatted certificate file.</p>
     *
     * <p><strong>Step-by-step encoding process:</strong></p>
     * <ol>
     *   <li>Start with a PEM file containing certificate(s) with headers:
     *   <pre>
     *   -----BEGIN CERTIFICATE-----
     *   MIIDRzCCAi+gAwIBAgIQ...
     *   -----END CERTIFICATE-----
     *   </pre>
     *   </li>
     *   <li>Apply Base64 encoding to the <strong>entire PEM file content</strong> (including headers and footers):
     *   <pre>
     *   base64 -i certificate.pem
     *   </pre>
     *   This produces a string like: {@code LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...}
     *   </li>
     *   <li>Pass this Base64-encoded string to this method</li>
     * </ol>
     *
     * <p><strong>What this method does internally:</strong></p>
     * <ul>
     *   <li>Decodes the Base64 string once to recover the original PEM-formatted content</li>
     *   <li>Counts occurrences of {@code -----BEGIN CERTIFICATE-----} headers</li>
     *   <li>Returns {@code true} if multiple certificates are found (chain), {@code false} if only one</li>
     * </ul>
     *
     * <p><strong>Example - Single Certificate:</strong></p>
     * <pre>
     * Original PEM file (certificate.pem):
     * -----BEGIN CERTIFICATE-----
     * MIIDRzCCAi+gAwIBAgIQ...
     * -----END CERTIFICATE-----
     *
     * Encoding command:
     * base64 -i certificate.pem
     *
     * Result: This method returns {@code false}
     * </pre>
     *
     * <p><strong>Example - Certificate Chain:</strong></p>
     * <pre>
     * Original PEM file (chain.pem):
     * -----BEGIN CERTIFICATE-----
     * MIIDRzCCAi+gAwIBAgIQ...  (Leaf Certificate)
     * -----END CERTIFICATE-----
     * -----BEGIN CERTIFICATE-----
     * MIIEADCCAuigAwIBAgIR...  (Intermediate CA)
     * -----END CERTIFICATE-----
     * -----BEGIN CERTIFICATE-----
     * MIIDdzCCAl+gAwIBAgIJ...  (Root CA)
     * -----END CERTIFICATE-----
     *
     * Encoding command:
     * base64 -i chain.pem
     *
     * Result: This method returns {@code true}
     * </pre>
     *
     * <p><strong>Common Misconception:</strong></p>
     * <p>This method expects exactly ONE Base64 encoding operation applied to the PEM file:</p>
     * <ul>
     *   <li>✅ Correct: {@code Base64(complete-PEM-file)} - Encode the entire PEM file once</li>
     *   <li>❌ Wrong: {@code Raw DER/binary certificate bytes} - Missing PEM structure and encoding</li>
     *   <li>❌ Wrong: {@code PEM file without Base64 encoding} - Missing the required encoding layer</li>
     * </ul>
     * <p><strong>Note:</strong> PEM files internally contain base64-encoded certificate data between the headers.
     * We are NOT encoding that data again - we are encoding the <em>entire PEM file</em> (headers + base64 content)
     * for safe storage in configuration systems.</p>
     *
     * @param base64EncodedCertContent the Base64-encoded PEM certificate file content.
     *                                 Must be the result of encoding a PEM file (with headers) using Base64.
     *                                 Example: output of {@code base64 -i certificate.pem} or
     *                                 {@code Base64.getEncoder().encodeToString(Files.readAllBytes(Paths.get("certificate.pem")))}
     * @return {@code true} if the decoded content contains multiple certificates (a chain),
     *         {@code false} if it contains a single certificate
     * @throws SdkException if the decoded content doesn't contain valid PEM certificate headers
     */
    public static boolean possibleChainOfCerts(final String base64EncodedCertContent) {
        // Decode the Base64 string ONCE to get back the original PEM-formatted content
        // Expected result after decoding: PEM text with "-----BEGIN CERTIFICATE-----" headers
        String rawCertFile = new String(Base64.getDecoder().decode(base64EncodedCertContent));

        // Count how many certificate headers are present in the PEM content
        int certCount = countOccurrencesOfBEGINCERT(rawCertFile);

        if (certCount == 1) {
            log.info("only one cert provided");
            return false;
        } else if (certCount > 1) {
            log.info("possible chain of certificates (found {} certificates)", certCount);
            return true;
        } else {
            // No valid certificate headers found - input format is incorrect
            log.error("cert not provided correctly - no PEM headers found after Base64 decoding");
            throw SdkException.builder()
                    .message("Certificate not provided correctly. Expected Base64-encoded PEM format with certificate headers.")
                    .build();
        }
    }

    public static X509CertificateChain resolveCertificateChain(final String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        var x509CertificateChain = new X509CertificateChain();
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
        var sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(x509Cert);
        } catch (IOException e) {
            throw SdkException.builder().cause(e).build();
        }
        return Base64.getEncoder().encodeToString(sw.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Extracts a private key from a Base64-encoded PEM private key file.
     *
     * <p><strong>Input Format:</strong> Base64(PEM-formatted-private-key)</p>
     * <p>The input must be the result of Base64-encoding a complete PEM private key file,
     * including the appropriate headers. Supports both PKCS#1 and PKCS#8 formats.</p>
     *
     * <p><strong>Supported PEM formats:</strong></p>
     * <ul>
     *   <li>PKCS#1 RSA: {@code -----BEGIN RSA PRIVATE KEY-----}</li>
     *   <li>PKCS#1 EC: {@code -----BEGIN EC PRIVATE KEY-----}</li>
     *   <li>PKCS#8: {@code -----BEGIN PRIVATE KEY-----}</li>
     * </ul>
     *
     * <p><strong>Example - PKCS#1 format:</strong></p>
     * <pre>
     * Original PEM file (private-key.pem):
     * -----BEGIN RSA PRIVATE KEY-----
     * MIIEpAIBAAKCAQEA...
     * -----END RSA PRIVATE KEY-----
     *
     * Encoding command:
     * base64 -i private-key.pem
     * </pre>
     *
     * <p><strong>Example - PKCS#8 format:</strong></p>
     * <pre>
     * Original PEM file (private-key.pem):
     * -----BEGIN PRIVATE KEY-----
     * MIIEvQIBADANBgkq...
     * -----END PRIVATE KEY-----
     *
     * Encoding command:
     * base64 -i private-key.pem
     * </pre>
     *
     * <p><strong>Important:</strong> Like certificate encoding, this uses a <strong>single layer of Base64 encoding</strong>.
     * Do NOT double-encode the private key.</p>
     *
     * @param base64EncodedPrivateKey Base64-encoded PEM private key (PKCS#1 or PKCS#8 format, single encoding layer)
     * @return the parsed private key (RSA or EC)
     * @throws SdkException if key parsing fails or format is unsupported
     */
    public static PrivateKey extractPrivateKey(final String base64EncodedPrivateKey) {
        // Decode the Base64 ONCE to get the original PEM content
        var privateKeyBytes = Base64.getDecoder().decode(base64EncodedPrivateKey);
        try {
            return privateKeyResolver(privateKeyBytes);
        } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw SdkException.builder().cause(e).build();
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
            throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
        }
        return keyType;
    }

    public static PrivateKey privateKeyResolver(final byte[] key) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        var byteArrayInputStream = new ByteArrayInputStream(key);
        var pemParser = new PEMParser(new InputStreamReader(byteArrayInputStream));
        var inputPemObject = pemParser.readObject();

        PrivateKeyInfo privateKeyInfo;
        String originalFormat;

        if (inputPemObject instanceof PEMKeyPair keyPair) {
            // Handle PKCS#1 format (RSA PRIVATE KEY, EC PRIVATE KEY, etc.)
            originalFormat = "PKCS#1";
            privateKeyInfo = keyPair.getPrivateKeyInfo();
            log.info("Private key Input format: PKCS#1 (Traditional format)");
        } else if (inputPemObject instanceof PrivateKeyInfo instancePrivateKeyInfo) {
            // Handle PKCS#8 format (PRIVATE KEY)
            originalFormat = "PKCS#8";
            privateKeyInfo = instancePrivateKeyInfo;
            log.info("Private key Input format: PKCS#8 (Modern format)");
        } else {
            throw new IllegalArgumentException("Unsupported key format: " + inputPemObject.getClass().getName() +
                    ". Supported formats: PKCS#1 (RSA/EC PRIVATE KEY) and PKCS#8 (PRIVATE KEY)");
        }

        // Extract algorithm and create key
        var encodedKey = privateKeyInfo.getEncoded();
        var algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        var keyType = resolveKeyType(algorithm);

        var keySpec = new PKCS8EncodedKeySpec(encodedKey);
        var keyFactory = KeyFactory.getInstance(keyType, "BC");
        var privateKey = keyFactory.generatePrivate(keySpec);

        log.info("Private key successfully loaded. Original format: {}, Private key algorithm: {}, internal format: {}", originalFormat, privateKey.getAlgorithm(), privateKey.getFormat());

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
        if (StringUtils.isBlank(str)) {
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
