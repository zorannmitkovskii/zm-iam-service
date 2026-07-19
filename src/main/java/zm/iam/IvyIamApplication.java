package zm.iam;

import zm.iam.keycloak.config.KeycloakProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point for zm-iam-service — the central Identity and Access Management
 * facade in front of Keycloak.
 *
 * <p>See {@code docs/iam-service-functional.md} and {@code iam-service-technical.md}
 * in the monorepo root for the full spec.
 */
@SpringBootApplication
@ConfigurationPropertiesScan(basePackageClasses = KeycloakProperties.class)
public class IvyIamApplication {

    public static void main(String[] args) {
        SpringApplication.run(IvyIamApplication.class, args);
    }
}
