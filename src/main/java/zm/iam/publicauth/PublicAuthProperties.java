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

    /**
     * Realm → the realm role that makes an organizer the owner of the
     * organization they signed up for. Products name that role differently —
     * Ivy calls its agency owner {@code AGENCY} — and granting a name the
     * product does not recognise leaves a signed-up agency acting as a plain
     * user. Realms not listed get {@link #DEFAULT_ORGANIZER_OWNER_ROLE}.
     */
    private Map<String, String> organizerOwnerRoles = new HashMap<>();

    /** The platform's original name for an organization's owner. */
    public static final String DEFAULT_ORGANIZER_OWNER_ROLE = "ORG_ADMIN";

    public String organizerOwnerRoleFor(String realm) {
        String role = realm == null ? null : organizerOwnerRoles.get(realm);
        return role == null || role.isBlank() ? DEFAULT_ORGANIZER_OWNER_ROLE : role.trim();
    }
}
