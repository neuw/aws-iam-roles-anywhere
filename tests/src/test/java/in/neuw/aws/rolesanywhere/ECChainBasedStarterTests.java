package in.neuw.aws.rolesanywhere;

import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.mocks.MockAwsServer;
import in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper;
import in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper.SESSIONS_URI;
import static in.neuw.aws.rolesanywhere.utils.CertificateChainGeneratorTestUtil.generateCertificateChainText;
import static in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorTestUtil.convertToOpenSSLFormat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static software.amazon.awssdk.regions.Region.AP_SOUTH_1;

@SpringBootTest(classes = TestApplication.class)
@TestPropertySource(properties = {
        "aws.iam.rolesanywhere.region=ap-south-1",
        "aws.iam.rolesanywhere.role-arn=arn:aws:iam::123456789012:role/test-role",
        "aws.iam.rolesanywhere.profile-arn=arn:aws:rolesanywhere:us-east-1:123456789012:profile/unique-uuid",
        "aws.iam.rolesanywhere.trust-anchor-arn=arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/unique-uuid",
        "aws.iam.rolesanywhere.role-session-name=test-role-session-name",
        "aws.iam.rolesanywhere.duration-seconds=3600",
        "aws.iam.rolesanywhere.prefetch=true",
        "aws.iam.rolesanywhere.async-credential-update-enabled=true"
})
class ECChainBasedStarterTests {

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
        mockedStatic.when(() -> AwsX509SigningHelper.resolveUri(any()))
                .thenReturn("http://localhost:28090" + SESSIONS_URI);
    }

    @Autowired
    private ConfigurableEnvironment environment;

    @Autowired
    private AwsCredentialsProvider awsCredentialsProvider;

    @BeforeAll
    static void init() {
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

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) throws Exception {
        // Generate test data before context startup
        var rsaKeyPair = KeyPairGeneratorTestUtil.generateKeyPair("EC", "secp384r1");
        var rsaKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(rsaKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var rsaCertChain = generateCertificateChainText("EC", rsaKeyPair);

        registry.add("aws.iam.rolesanywhere.region", AP_SOUTH_1::id);
        registry.add("aws.iam.rolesanywhere.role-arn", () -> "arn:aws:iam::123456789012:role/test-role");
        registry.add("aws.iam.rolesanywhere.profile-arn", () -> "arn:aws:rolesanywhere:us-east-1:123456789012:profile/unique-uuid");
        registry.add("aws.iam.rolesanywhere.trust-anchor-arn", () -> "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/unique-uuid");
        registry.add("aws.iam.rolesanywhere.role-session-name", () -> "test-role-session-name");
        registry.add("aws.iam.rolesanywhere.duration-seconds", () -> "3600");
        registry.add("aws.iam.rolesanywhere.encoded-private-key", () -> rsaKeyBase64);
        registry.add("aws.iam.rolesanywhere.encoded-x509-certificate", () -> rsaCertChain);
        registry.add("aws.iam.rolesanywhere.prefetch", () -> "true");
        registry.add("aws.iam.rolesanywhere.async-credential-update-enabled", () -> "true");
    }

    @Test
    @DirtiesContext
    void contextLoadTest() {
        assertEquals(IAMRolesAnywhereSessionsCredentialsProvider.class, awsCredentialsProvider.getClass());
    }

}
