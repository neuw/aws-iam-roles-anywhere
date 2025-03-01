package in.neuw.aws.rolesanywhere.credentials.models;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
public class CredentialSet {

    private AssumedRoleUser assumedRoleUser;
    private Credentials credentials;
    private int packedPolicySize;
    private String roleArn;
    private String sourceIdentity;

}