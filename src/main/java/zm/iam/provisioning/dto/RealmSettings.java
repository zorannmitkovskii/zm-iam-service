package zm.iam.provisioning.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Positive;

/**
 * Realm-level toggles copied straight into
 * {@link org.keycloak.representations.idm.RealmRepresentation} at
 * reconciliation time (IAM-04). Null values mean "let Keycloak default
 * stand" — the manifest is additive, not exhaustive.
 *
 * <p>The two session lifespans are in seconds and are what decide how long a
 * refresh token keeps somebody signed in: the idle timeout is how long a
 * session survives unused, the max lifespan how long it can last at all.
 * Keycloak's defaults (30 minutes, 10 hours) sign a user out over lunch.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record RealmSettings(
        Boolean loginWithEmailAllowed,
        Boolean registrationAllowed,
        Boolean resetPasswordAllowed,
        Boolean rememberMe,
        Boolean verifyEmail,

        @Positive(message = "ssoSessionIdleTimeoutSeconds must be positive")
        Integer ssoSessionIdleTimeoutSeconds,

        @Positive(message = "ssoSessionMaxLifespanSeconds must be positive")
        Integer ssoSessionMaxLifespanSeconds
) {

    /** A session cannot idle for longer than it is allowed to live at all.
     *  {@link JsonIgnore} for the same round-trip reason as the manifest's own checks. */
    @JsonIgnore
    @AssertTrue(message = "ssoSessionIdleTimeoutSeconds must not exceed ssoSessionMaxLifespanSeconds")
    public boolean isSessionIdleWithinMax() {
        return ssoSessionIdleTimeoutSeconds == null
                || ssoSessionMaxLifespanSeconds == null
                || ssoSessionIdleTimeoutSeconds <= ssoSessionMaxLifespanSeconds;
    }
}
