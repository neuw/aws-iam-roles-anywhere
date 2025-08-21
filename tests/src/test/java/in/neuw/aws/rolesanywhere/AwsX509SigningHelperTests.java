package in.neuw.aws.rolesanywhere;

import in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import software.amazon.awssdk.regions.Region;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;

class AwsX509SigningHelperTests {

    @Test
    void resolveHostBasedOnRegionTest() {
        assertEquals("rolesanywhere.ap-south-1.amazonaws.com", AwsX509SigningHelper.resolveHostBasedOnRegion(Region.AP_SOUTH_1));
    }

    @Test
    void resolveHostEndpointTest() {
        assertEquals("https://rolesanywhere.ap-south-1.amazonaws.com", AwsX509SigningHelper.resolveHostEndpoint(Region.AP_SOUTH_1));
    }

    @Test
    void testHash_NoSuchAlgorithmException() {
        String testText = "test content";

        try (MockedStatic<MessageDigest> mockedMessageDigest = mockStatic(MessageDigest.class)) {
            mockedMessageDigest.when(() -> MessageDigest.getInstance("SHA-256"))
                    .thenThrow(new NoSuchAlgorithmException("Algorithm not available"));

            // @SneakyThrows converts this to RuntimeException
            assertThrows(NoSuchAlgorithmException.class, () -> {
                AwsX509SigningHelper.hash(testText);
            });

            mockedMessageDigest.verify(() -> MessageDigest.getInstance("SHA-256"));
        }
    }

}
