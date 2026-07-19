package zm.iam.provisioning.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Realm-level toggles copied straight into
 * {@link org.keycloak.representations.idm.RealmRepresentation} at
 * reconciliation time (IAM-04). Null values mean "let Keycloak default
 * stand" — the manifest is additive, not exhaustive.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record RealmSettings(
        Boolean loginWithEmailAllowed,
        Boolean registrationAllowed,
        Boolean resetPasswordAllowed,
        Boolean rememberMe,
        Boolean verifyEmail
) {
}
