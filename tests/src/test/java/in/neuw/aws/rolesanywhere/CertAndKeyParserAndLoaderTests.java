package in.neuw.aws.rolesanywhere;

import in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader;
import in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader.EC;
import static in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader.EC_OID;

class CertAndKeyParserAndLoaderTests {

    @Test
    void ECkeyResolveSignatureAlgorithmTest() throws Exception {
        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var alg = CertAndKeyParserAndLoader.resolveSignatureAlgorithm(ecKeyPair.getPrivate());
        Assertions.assertEquals("SHA256withECDSA", alg);
    }

    @Test
    void RSAkeyResolveSignatureAlgorithmTest() throws Exception {
        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var alg = CertAndKeyParserAndLoader.resolveSignatureAlgorithm(rsaKeyPair.getPrivate());
        Assertions.assertEquals("SHA256withRSA", alg);
    }

    @Test
    void DSAkeyResolveSignatureAlgorithmTest() throws NoSuchAlgorithmException {
        var dsaKeyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            // only RSA or EC are supported with util
            CertAndKeyParserAndLoader.resolveSignatureAlgorithm(dsaKeyPair.getPrivate());
        });
    }

    @Test
    void dsaResolveAndValidateAlgorithmTest() throws NoSuchAlgorithmException {
        var dsaKeyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            // only RSA or EC are supported with util
            CertAndKeyParserAndLoader.resolveAndValidateAlgorithm(dsaKeyPair.getPrivate());
        });
    }

    @Test
    void ecResolveKeyTypeTest() {
        // only RSA or EC are supported with util
        Assertions.assertEquals(EC, CertAndKeyParserAndLoader.resolveKeyType(ASN1ObjectIdentifier.tryFromID(EC_OID)));
    }

    @Test
    void wrongResolveKeyTypeTest() {
        // only RSA or EC are supported with util
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            // wrong ID
            CertAndKeyParserAndLoader.resolveKeyType(ASN1ObjectIdentifier.tryFromID("1.2.840.10045.2.1.1"));
        });
    }

    @Test
    void countOccurrencesOfBEGINCERTNegativeTest() {
        Assertions.assertThrows(SdkException.class, () -> {
            CertAndKeyParserAndLoader.possibleChainOfCerts(Base64.getEncoder().encodeToString("test".getBytes(StandardCharsets.UTF_8)));
        });
    }

    @Test
    void blankCertStringNegativeTest() {
        Assertions.assertThrows(SdkException.class, () -> {
            CertAndKeyParserAndLoader.possibleChainOfCerts(Base64.getEncoder().encodeToString("".getBytes(StandardCharsets.UTF_8)));
        });
    }

}
