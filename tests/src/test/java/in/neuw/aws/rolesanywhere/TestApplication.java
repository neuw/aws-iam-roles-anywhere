package in.neuw.aws.rolesanywhere;

import in.neuw.aws.rolesanywhere.config.AwsRolesAnywhereStarterConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import(AwsRolesAnywhereStarterConfig.class)
public class TestApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(TestApplication.class, args);
    }
}