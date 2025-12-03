package in.neuw.aws.rolesanywhere.config;

import in.neuw.aws.rolesanywhere.config.props.AwsRolesAnywhereStarterProperties;
import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.credentials.RolesAnywhereCredentialsProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import com.fasterxml.jackson.databind.ObjectMapper;

@AutoConfiguration
@EnableConfigurationProperties({AwsRolesAnywhereStarterProperties.class})
public class AwsRolesAnywhereStarterConfig {

    private final AwsRolesAnywhereStarterProperties awsRolesAnywhereStarterProperties;
    private final ObjectMapper jsonMapper;

    public AwsRolesAnywhereStarterConfig(final AwsRolesAnywhereStarterProperties awsRolesAnywhereStarterProperties,
                                         final ObjectMapper jsonMapper) {
        this.awsRolesAnywhereStarterProperties = awsRolesAnywhereStarterProperties;
        this.jsonMapper = jsonMapper;
    }

    @Bean
    public RolesAnywhereCredentialsProvider rolesAnywhereCredentialsProvider() {
        return new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(awsRolesAnywhereStarterProperties, jsonMapper)
                .prefetch(awsRolesAnywhereStarterProperties.getPrefetch())
                .asyncCredentialUpdateEnabled(awsRolesAnywhereStarterProperties.getAsyncCredentialUpdateEnabled())
                .build();
    }
}
