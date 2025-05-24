package in.neuw.aws.rolesanywhere.mocks;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.config.AwsRolesAnywhereStarterConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

@SpringBootApplication
@Import(AwsRolesAnywhereStarterConfig.class)
public class TestApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(TestApplication.class, args);
    }

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}