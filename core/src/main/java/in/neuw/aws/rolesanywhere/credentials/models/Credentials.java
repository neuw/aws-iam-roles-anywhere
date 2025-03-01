package in.neuw.aws.rolesanywhere.credentials.models;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
public class Credentials {

    private String accessKeyId;
    private String expiration;
    private String secretAccessKey;
    private String sessionToken;

}