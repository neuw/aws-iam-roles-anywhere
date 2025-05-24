package in.neuw.aws.rolesanywhere;

import in.neuw.aws.rolesanywhere.utils.AwsX509SigningHelper;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AwsX509SigningHelperTests {

    @Test
    void resolveHostBasedOnRegionTest() {
        assertEquals("rolesanywhere.ap-south-1.amazonaws.com", AwsX509SigningHelper.resolveHostBasedOnRegion(Region.AP_SOUTH_1));
    }

    @Test
    void resolveHostEndpointTest() {
        assertEquals("https://rolesanywhere.ap-south-1.amazonaws.com", AwsX509SigningHelper.resolveHostEndpoint(Region.AP_SOUTH_1));
    }

}
