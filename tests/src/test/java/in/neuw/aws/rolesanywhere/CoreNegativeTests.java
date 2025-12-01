package in.neuw.aws.rolesanywhere;

import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.mocks.MockAwsServer;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper;
import in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.utils.IoUtils;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

import static in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper.SESSIONS_URI;
import static in.neuw.aws.rolesanywhere.utils.CertificateChainGeneratorTestUtil.convertToPEM;
import static in.neuw.aws.rolesanywhere.utils.CertificateChainGeneratorTestUtil.generateCertificateChainText;
import static in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtil.convertToOpenSSLFormat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CoreNegativeTests {

    private final JsonMapper jsonMapper = new JsonMapper();

    private static MockedStatic<AwsX509SigningHelper> awsX509SigningHelperMockedStatic;
    private static MockedStatic<IoUtils> ioUtilsMockedStatic;
    private static MockedStatic<MessageDigest> messageDigestMockedStatic;

    static {
        // Initialize mock before Spring context
        awsX509SigningHelperMockedStatic = mockStatic(AwsX509SigningHelper.class, CALLS_REAL_METHODS);
        ioUtilsMockedStatic = mockStatic(IoUtils.class, CALLS_REAL_METHODS);
        messageDigestMockedStatic = mockStatic(MessageDigest.class, CALLS_REAL_METHODS);
    }

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
        MockAwsServer.init();
    }

    @AfterAll
    static void cleanup() {
        MockAwsServer.stopInstance();
        awsX509SigningHelperMockedStatic.close();
        awsX509SigningHelperMockedStatic = null;
        ioUtilsMockedStatic.close();
        ioUtilsMockedStatic = null;
        messageDigestMockedStatic.close();
        messageDigestMockedStatic = null;
    }

    @Test
    void emptyResponseErrorTest() throws Exception {
        awsX509SigningHelperMockedStatic.close();
        awsX509SigningHelperMockedStatic = null;
        awsX509SigningHelperMockedStatic = mockStatic(AwsX509SigningHelper.class, CALLS_REAL_METHODS);
        awsX509SigningHelperMockedStatic.when(() -> AwsX509SigningHelper.resolveUri(any()))
                .thenReturn("http://localhost:28090" + SESSIONS_URI + "-empty-response");

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecCertChain "+ecCertChain);
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(ecCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(IamException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, jsonMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });
        awsX509SigningHelperMockedStatic.verify(() -> AwsX509SigningHelper.resolveUri(any()), atLeastOnce());
    }

    @Test
    void successButEmptyResponseErrorTest() throws Exception {
        awsX509SigningHelperMockedStatic.close();
        awsX509SigningHelperMockedStatic = null;
        awsX509SigningHelperMockedStatic = mockStatic(AwsX509SigningHelper.class, CALLS_REAL_METHODS);
        awsX509SigningHelperMockedStatic.when(() -> AwsX509SigningHelper.resolveUri(any()))
                .thenReturn("http://localhost:28090" + SESSIONS_URI + "-success-empty-response");

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecCertChain "+ecCertChain);
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(ecCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(IamException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, jsonMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });
        awsX509SigningHelperMockedStatic.verify(() -> AwsX509SigningHelper.resolveUri(any()), atLeastOnce());
    }

    @Test
    void keyNoSuchAlgorithmExceptionTest() throws Exception {
        awsX509SigningHelperMockedStatic.when(() -> AwsX509SigningHelper.sign(any(), any()))
                .thenThrow(new NoSuchAlgorithmException("test"));

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecCertChain "+ecCertChain);
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(ecCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(RuntimeException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, jsonMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });

        awsX509SigningHelperMockedStatic.verify(() -> AwsX509SigningHelper.resolveUri(any()), atLeastOnce());
    }

    @Test
    void keySignatureExceptionTest() throws Exception {
        awsX509SigningHelperMockedStatic.when(() -> AwsX509SigningHelper.sign(any(), any()))
                .thenThrow(new SignatureException("test"));

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecCertChain "+ecCertChain);
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(ecCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(RuntimeException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, jsonMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });

        awsX509SigningHelperMockedStatic.verify(() -> AwsX509SigningHelper.resolveUri(any()), atLeastOnce());
    }

    @Test
    void keyInvalidKeyExceptionTest() throws Exception {
        awsX509SigningHelperMockedStatic.when(() -> AwsX509SigningHelper.sign(any(), any()))
                .thenThrow(new InvalidKeyException("test"));

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecCertChain "+ecCertChain);
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(ecCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(RuntimeException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, jsonMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });

        awsX509SigningHelperMockedStatic.verify(() -> AwsX509SigningHelper.resolveUri(any()), atLeastOnce());
    }

    @Test
    void ioUtilsExceptionTest() throws Exception {
        ioUtilsMockedStatic.when(() -> IoUtils.toUtf8String(any()))
                .thenThrow(new IOException("test"));

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecCertChain "+ecCertChain);
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(ecCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(RuntimeException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, jsonMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });

        awsX509SigningHelperMockedStatic.verify(() -> AwsX509SigningHelper.resolveUri(any()), atLeastOnce());
    }

}
