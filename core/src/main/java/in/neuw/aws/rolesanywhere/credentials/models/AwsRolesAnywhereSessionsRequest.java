package in.neuw.aws.rolesanywhere.credentials.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"roleArn", "profileArn", "trustAnchorArn", "sessionDuration"})
public class AwsRolesAnywhereSessionsRequest {

    private String roleArn;
    private String profileArn;
    private String trustAnchorArn;
    private Integer durationSeconds = 900;

}
