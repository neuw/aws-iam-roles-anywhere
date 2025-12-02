package in.neuw.aws.rolesanywhere;

import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnyWhereRequesterDetails;
import in.neuw.aws.rolesanywhere.credentials.models.AwsRolesAnywhereSessionsRequest;
import in.neuw.aws.rolesanywhere.mocks.MockAwsServer;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper;
import in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader;
import in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtil;
import in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtilV2;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import static in.neuw.aws.rolesanywhere.utils.CertificateChainGeneratorTestUtil.*;
import static in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtil.convertToOpenSSLFormat;
import static in.neuw.aws.rolesanywhere.utils.MockAwsRolesAnywhereSessionsResponseGeneratorTestUtil.mockAwsRolesAnywhereSessionsResponse;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@Slf4j
@ExtendWith(MockitoExtension.class)
class CoreTests {

    private final JsonMapper jsonMapper = new JsonMapper();

    private static MockedStatic<AwsX509SigningHelper> mockedStatic;

    static {
        // Initialize mock before Spring context
        mockedStatic = mockStatic(AwsX509SigningHelper.class, CALLS_REAL_METHODS);
        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });
        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostBasedOnRegion(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "localhost:28090";
                });
    }

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
        MockAwsServer.init();
    }

    @AfterAll
    static void cleanup() {
        MockAwsServer.stopInstance();
        if (mockedStatic != null) {
            mockedStatic.close();
            mockedStatic = null;
        }
    }

    @Test
    void ECKeyBasedChainPKCS8Test() throws Exception {
        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

        var ecKeyPair = KeyPairGeneratorTestUtilV2.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(KeyPairGeneratorTestUtilV2.convertToPKCS8Format(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
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

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .build();

        S3Client.builder().credentialsProvider(provider).region(Region.of("ap-south-1")).build();

        mockedStatic.verify(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                Mockito.any(SdkHttpClient.class),
                Mockito.any(JsonMapper.class)
        ), atLeastOnce());
    }

    @Test
    void ECKeyBasedChainTest() throws Exception {

        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

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

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .build();

        S3Client.builder().credentialsProvider(provider).region(Region.of("ap-south-1")).build();

        mockedStatic.verify(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                Mockito.any(SdkHttpClient.class),
                Mockito.any(JsonMapper.class)
        ), atLeastOnce());
    }

    @Test
    void RSAKeyBasedChainTest() throws Exception {

        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .build();

        S3Client.builder().credentialsProvider(provider).region(Region.of("ap-south-1")).build();

        mockedStatic.verify(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                Mockito.any(SdkHttpClient.class),
                Mockito.any(JsonMapper.class)
        ), atLeastOnce());
    }

    @Test
    void RSAKeyBasedChainPKCS8Test() throws Exception {

        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

        var rsaKeyPair = KeyPairGeneratorTestUtilV2.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(KeyPairGeneratorTestUtilV2.convertToPKCS8Format(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .build();

        S3Client.builder().credentialsProvider(provider).region(Region.of("ap-south-1")).build();

        mockedStatic.verify(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                Mockito.any(SdkHttpClient.class),
                Mockito.any(JsonMapper.class)
        ), atLeastOnce());
    }

    @Test
    void ECKeyBasedCertTest() throws Exception {

        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificate("EC", ecKeyPair);

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
        properties.setAsyncCredentialUpdateEnabled(false);

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .build();

        S3Client.builder().credentialsProvider(provider).region(Region.of("ap-south-1")).build();

        mockedStatic.verify(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                Mockito.any(SdkHttpClient.class),
                Mockito.any(JsonMapper.class)
        ), atLeastOnce());
    }

    @Test
    void testUnsupportedKeyFormat_Certificate() {
        String certificatePem = """
            -----BEGIN CERTIFICATE-----
            MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
            BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDlM8lz3BSDU58N
            +kO5BFWqr7xUdoOEKBL7bKPPq3wz6kCCJDLM6z6wq+HGz6zdm4k8zF4hO2B8wC0x
            +6c7V8rlAgMBAAEwDQYJKoZIhvcNAQELBQADQQCX6oVN/rtVsfVKArvNPkl8Hubr
            BeGnowpdDxdDSn5arhP3NUXwzUft1BibovuP+TxD2QHkveVkr1ebUHeuA==
            -----END CERTIFICATE-----
            """;

        byte[] certBytes = Base64.getEncoder().encode(certificatePem.getBytes());

        assertThrows(
            RuntimeException.class,
            () -> CertAndKeyParserAndLoader.extractPrivateKey(Base64.getEncoder().encodeToString(certBytes))
        );

    }

    @Test
    void wrongCertTest() throws Exception {

        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        // mocked dirty value
        var ecCertChain = Base64.getEncoder().encodeToString("GIBBERISH_NOT_A_CERT_OR_CERT_CHAIN".getBytes(StandardCharsets.UTF_8));

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
    }

    @Test
    void builderPropsTest() throws Exception {
        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificate("EC", ecKeyPair); // actual

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
        properties.setAsyncCredentialUpdateEnabled(false);

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .durationSeconds(3600)
                .roleArn("test-something")
                .profileArn("test-something")
                .encodedPrivateKey(ecKeyBase64)
                .encodedX509Certificate(ecCertChain)
                .roleSessionName("something")
                .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                .prefetch(false)
                .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                .region("ap-south-1")
                .trustAnchorArn("test-something")
                .build();

        assertEquals(Duration.of(1, ChronoUnit.MINUTES), provider.staleTime());
        assertEquals(Duration.of(3, ChronoUnit.MINUTES), provider.prefetchTime());

        S3Client.builder().credentialsProvider(provider).region(Region.of("ap-south-1")).build();
    }

    @Test
    void providerCopyTest() throws Exception {
        mockedStatic.when(() -> AwsX509SigningHelper.getIamRolesAnywhereSessions(
                        Mockito.any(AwsRolesAnywhereSessionsRequest.class),
                        Mockito.any(AwsRolesAnyWhereRequesterDetails.class),
                        Mockito.any(SdkHttpClient.class),
                        Mockito.any(JsonMapper.class)
                )
        ).thenAnswer(invocation -> mockAwsRolesAnywhereSessionsResponse());

        var ecKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificate("EC", ecKeyPair); // actual

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
        properties.setAsyncCredentialUpdateEnabled(false);

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .durationSeconds(3600)
                .roleArn("test-something")
                .profileArn("test-something")
                .encodedPrivateKey(ecKeyBase64)
                .encodedX509Certificate(ecCertChain)
                .roleSessionName("something")
                .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                .prefetch(false)
                .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                .region("ap-south-1")
                .trustAnchorArn("test-something")
                .build();

        var providerClone = provider.copy(p -> {
            p.durationSeconds(3600);
            p.region("ap-south-1");
            p.trustAnchorArn("test-something");
            p.profileArn("test-something");
            p.encodedPrivateKey(ecKeyBase64);
            p.encodedX509Certificate(ecCertChain);
            p.roleArn("test-something");
            p.roleSessionName("something-else");
        });

        assertEquals(Duration.of(1, ChronoUnit.MINUTES), provider.staleTime());
        assertEquals(Duration.of(3, ChronoUnit.MINUTES), provider.prefetchTime());

        assertNotEquals(provider, providerClone);

        var builder = provider.toBuilder();
        builder.roleSessionName("some-other-value");
        var newProvider = builder.durationSeconds(3600)
                .region("ap-south-1")
                .trustAnchorArn("test-something")
                .roleArn("test-something")
                .profileArn("test-something")
                .encodedPrivateKey(ecKeyBase64)
                .encodedX509Certificate(ecCertChain)
                .build();

        assertNotEquals(providerClone, newProvider);
    }

    @Test
    void RSAKeyBasedCertTest() throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificate("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .build();

        assertEquals(Duration.of(5, ChronoUnit.MINUTES), provider.prefetchTime());
    }

    @Test
    void RSAKeyBasedCertWithChainTest() throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        var provider = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, jsonMapper)
                .prefetch(properties.getPrefetch())
                .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                .build();

        assertEquals(Duration.of(5, ChronoUnit.MINUTES), provider.prefetchTime());
    }

    @Test
    void builderIssuesDurationNotPresentTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .roleArn("test-something")
                    .profileArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesDurationSecondsIncorrectTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(0)
                    .roleArn("test-something")
                    .profileArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesDurationSecondsNotValidTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(3600*14 + 1)
                    .roleArn("test-something")
                    .profileArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesRoleArnNotPresentTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(3600)
                    .profileArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesTrustArnNotPresentTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(3600)
                    .roleArn("test-something")
                    .profileArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesProfileArnNotPresentTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(3600)
                    .roleArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesPrivateKeyNotPresentTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(3600)
                    .roleArn("test-something")
                    .profileArn("test-something")
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesCertNotPresentTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(3600)
                    .roleArn("test-something")
                    .profileArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .region("ap-south-1")
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

    @Test
    void builderIssuesRegionNotPresentTest(TestInfo testInfo) throws Exception {

        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("RSA", 2048);
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("RSA", rsaKeyPair);

        System.out.println("CertChain "+rsaCertChain);
        System.out.println("KeyBase64 "+rsaKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(rsaKeyBase64);
        properties.setEncodedX509Certificate(rsaCertChain);
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        mockedStatic.when(() -> AwsX509SigningHelper.resolveHostEndpoint(any(Region.class)))
                .thenAnswer(invocation -> {
                    return "http://localhost:28090";
                });

        try {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(jsonMapper)
                    .durationSeconds(3600)
                    .roleArn("test-something")
                    .profileArn("test-something")
                    .encodedPrivateKey(rsaKeyBase64)
                    .encodedX509Certificate(rsaCertChain)
                    .roleSessionName("something")
                    .prefetchTime(Duration.of(3, ChronoUnit.MINUTES))
                    .prefetch(false)
                    .staleTime(Duration.of(1, ChronoUnit.MINUTES))
                    .trustAnchorArn("test-something")
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        } catch (IllegalArgumentException e) {
            log.info("Illegal Argument Exception for the test - {}", testInfo.getTestMethod().orElseThrow().getName());
        }
    }

}
