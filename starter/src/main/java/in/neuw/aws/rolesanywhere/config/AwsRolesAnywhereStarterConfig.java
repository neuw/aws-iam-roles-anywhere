package in.neuw.aws.rolesanywhere.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.config.props.AwsRolesAnywhereStarterProperties;
import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.credentials.RolesAnywhereCredentialsProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties({AwsRolesAnywhereStarterProperties.class})
public class AwsRolesAnywhereStarterConfig {

    private final AwsRolesAnywhereStarterProperties awsRolesAnywhereStarterProperties;
    private final ObjectMapper objectMapper;

    public AwsRolesAnywhereStarterConfig(final AwsRolesAnywhereStarterProperties awsRolesAnywhereStarterProperties,
                                         final ObjectMapper objectMapper) {
        this.awsRolesAnywhereStarterProperties = awsRolesAnywhereStarterProperties;
        this.objectMapper = objectMapper;
    }

    @Bean
    public RolesAnywhereCredentialsProvider rolesAnywhereCredentialsProvider() {
        return new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(awsRolesAnywhereStarterProperties, objectMapper)
                .prefetch(awsRolesAnywhereStarterProperties.getPrefetch())
                .asyncCredentialUpdateEnabled(awsRolesAnywhereStarterProperties.getAsyncCredentialUpdateEnabled())
                .build();
    }
}
