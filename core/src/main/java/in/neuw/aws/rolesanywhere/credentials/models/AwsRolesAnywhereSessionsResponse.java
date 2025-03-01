package in.neuw.aws.rolesanywhere.credentials.models;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.List;

@Getter
@Setter
@Accessors(chain = true)
public class AwsRolesAnywhereSessionsResponse {
    private List<CredentialSet> credentialSet;

    private String subjectArn;
}