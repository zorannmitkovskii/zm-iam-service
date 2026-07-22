package zm.iam.publicauth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

/**
 * Maps incoming public-auth requests to the Keycloak realm they target.
 * Bound from {@code iam.public-auth.*}. Consumed by {@link RealmResolver}.
 *
 * <p>Top-level (not nested in {@code RealmResolver}) on purpose:
 * {@code @ConfigurationPropertiesScan} does not register a
 * {@code @ConfigurationProperties} class whose enclosing class is a
 * {@code @Component}, so nesting it left the bean uncreated at startup.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "iam.public-auth")
public class PublicAuthProperties {

    /** Origin host → realm. */
    private Map<String, String> originToRealm = new HashMap<>();

    /** Explicit appId (from body) → realm. */
    private Map<String, String> appIdToRealm = new HashMap<>();
}
