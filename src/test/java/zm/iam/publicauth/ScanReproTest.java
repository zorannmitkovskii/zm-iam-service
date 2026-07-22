package zm.iam.publicauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import zm.iam.keycloak.config.KeycloakProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard for the startup failure where {@code PublicAuthProperties}
 * was a nested class inside the {@code @Component} {@link RealmResolver}:
 * {@code @ConfigurationPropertiesScan} skips a {@code @ConfigurationProperties}
 * class whose enclosing class is a component, so the props bean was never
 * created and {@code RealmResolver} failed to construct.
 *
 * <p>With {@link PublicAuthProperties} extracted to a top-level class, the
 * scan registers it and the resolver wires up cleanly.
 */
class ScanReproTest {

    // Mimic the real app: component-scan picks up @Component RealmResolver,
    // and @ConfigurationPropertiesScan registers the props (both base classes).
    @Configuration
    @ComponentScan(
            basePackages = "zm.iam.publicauth",
            useDefaultFilters = false,
            includeFilters = @ComponentScan.Filter(
                    type = FilterType.ASSIGNABLE_TYPE, classes = RealmResolver.class))
    @ConfigurationPropertiesScan(basePackageClasses = {KeycloakProperties.class, RealmResolver.class})
    static class ScanConfig {}

    @Test
    @DisplayName("props bean registers and RealmResolver wires up without startup failure")
    void nestedConfigPropsBeanIsRegistered() {
        new ApplicationContextRunner()
                .withUserConfiguration(ScanConfig.class)
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(PublicAuthProperties.class);
                    assertThat(ctx).hasSingleBean(RealmResolver.class);
                });
    }
}
