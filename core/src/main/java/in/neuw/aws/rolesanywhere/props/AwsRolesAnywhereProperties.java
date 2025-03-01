package in.neuw.aws.rolesanywhere.props;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AwsRolesAnywhereProperties {

    private String roleArn;
    private String profileArn;
    private String trustAnchorArn;
    private String region;
    private Integer durationSeconds;
    private String roleSessionName;
    private String encodedX509Certificate;
    private String encodedPrivateKey;
    private Boolean prefetch = true;
    private Boolean asyncCredentialUpdateEnabled = false;

}
