package in.neuw.aws.rolesanywhere;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.mocks.MockAwsServer;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.exception.SdkException;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import static in.neuw.aws.rolesanywhere.utils.CertAndKeyParserAndLoader.BEGIN_CERT;
import static in.neuw.aws.rolesanywhere.utils.CertificateChainReferencingGenerator.convertToPEM;
import static in.neuw.aws.rolesanywhere.utils.CertificateChainReferencingGenerator.generateCertificateChainText;
import static in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorUtil.convertToOpenSSLFormat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class CoreNegativeV2Tests {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static MockedStatic<CertificateFactory> certificateFactoryMockedStatic;

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
        MockAwsServer.init();
    }

    @BeforeEach
    void initEveryTime() {
        certificateFactoryMockedStatic = mockStatic(CertificateFactory.class, CALLS_REAL_METHODS);
    }

    @AfterEach
    void cleanup() {
        if (certificateFactoryMockedStatic != null) {
            certificateFactoryMockedStatic.close();
            certificateFactoryMockedStatic = null;
        }
    }

    @AfterAll
    static void tearDown() {
        MockAwsServer.stopInstance();
    }

    @Test
    void noSuchProviderExceptionErrorTest() throws Exception {
        var ecKeyPair = KeyPairGeneratorUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        certificateFactoryMockedStatic.when(() -> CertificateFactory.getInstance("X.509", "BC"))
                .thenThrow(new NoSuchProviderException("BC provider not found"));

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

        assertThrows(NoSuchProviderException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, objectMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });
    }

    @Test
    void certNotGoodTest() throws Exception {
        var ecKeyPair = KeyPairGeneratorUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(Base64.getEncoder().encodeToString("test".getBytes(StandardCharsets.UTF_8)));
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(SdkException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, objectMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });
    }

    @Test
    void certNotGoodV2Test() throws Exception {
        var ecKeyPair = KeyPairGeneratorUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));

        System.out.println(convertToPEM(ecKeyPair.getPrivate()));
        System.out.println("ecKeyBase64 "+ecKeyBase64);

        var properties = new AwsRolesAnywhereProperties();
        properties.setEncodedPrivateKey(ecKeyBase64);
        properties.setEncodedX509Certificate(Base64.getEncoder().encodeToString((BEGIN_CERT+"test").getBytes(StandardCharsets.UTF_8)));
        properties.setRoleArn("test");
        properties.setProfileArn("test");
        properties.setTrustAnchorArn("test");
        properties.setPrefetch(true);
        properties.setRegion("ap-south-1");
        properties.setDurationSeconds(3600);
        properties.setAsyncCredentialUpdateEnabled(true);

        assertThrows(SdkException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, objectMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });
    }

    @Test
    void certificateExceptionErrorTest() throws Exception {
        var ecKeyPair = KeyPairGeneratorUtil.generateKeyPair("EC", "secp384r1");
        var ecKeyBase64 = Base64.getEncoder().encodeToString(convertToOpenSSLFormat(ecKeyPair.getPrivate()).getBytes(StandardCharsets.UTF_8));
        var ecCertChain = generateCertificateChainText("EC", ecKeyPair);

        certificateFactoryMockedStatic.when(() -> CertificateFactory.getInstance("X.509", "BC"))
                .thenThrow(new CertificateException("test dummy!!"));

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

        assertThrows(CertificateException.class, () -> {
            new IAMRolesAnywhereSessionsCredentialsProvider
                    .Builder(properties, objectMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });
    }

}
