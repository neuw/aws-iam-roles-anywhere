package in.neuw.aws.rolesanywhere;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.mocks.MockAwsServer;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper;
import in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import static in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper.SESSIONS_URI;
import static in.neuw.aws.rolesanywhere.utils.CertificateChainReferencingGenerator.convertToPEM;
import static in.neuw.aws.rolesanywhere.utils.CertificateChainReferencingGenerator.generateCertificateChainText;
import static in.neuw.aws.rolesanywhere.utils.KeyPairGeneratorUtil.convertToOpenSSLFormat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class CoreNegativeTests {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static MockedStatic<AwsX509SigningHelper> mockedStatic;

    static {
        // Initialize mock before Spring context
        mockedStatic = mockStatic(AwsX509SigningHelper.class, CALLS_REAL_METHODS);
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
    void emptyResponseErrorTest() throws Exception {
        mockedStatic.when(() -> AwsX509SigningHelper.resolveUri(any())).thenAnswer(invocation -> {
            return "http://localhost:8090"+SESSIONS_URI+"-empty-response";
        });

        var ecKeyPair = KeyPairGeneratorUtil.generateKeyPair("EC", "secp384r1");
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
                    .Builder(properties, objectMapper)
                    .prefetch(properties.getPrefetch())
                    .asyncCredentialUpdateEnabled(properties.getAsyncCredentialUpdateEnabled())
                    .build();
        });
    }

}
