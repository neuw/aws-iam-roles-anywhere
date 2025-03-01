package in.neuw.aws.rolesanywhere.config.props;

import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "aws.iam.rolesanywhere")
public class AwsRolesAnywhereStarterProperties extends AwsRolesAnywhereProperties implements InitializingBean {

    @Override
    public void afterPropertiesSet() throws Exception {
        // TODO validate properties here.
    }
}
