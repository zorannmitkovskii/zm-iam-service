package zm.iam.provisioning.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.List;

/**
 * A Keycloak OIDC client declared in a manifest. Public vs confidential,
 * PKCE toggle, redirect URIs, and (for service accounts) which realm roles
 * to bind.
 *
 * <p>Redirect URIs allow a single {@code *} wildcard suffix — Keycloak's
 * own convention — validated in {@link RealmDeclaration}'s cross-field
 * checks rather than per-URI here to keep this record purely structural.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record ClientDeclaration(
        @NotBlank(message = "clientId is required")
        @Pattern(regexp = "[a-zA-Z0-9-_]+",
                message = "clientId must match [a-zA-Z0-9-_]+")
        String clientId,

        @NotNull(message = "client type is required (PUBLIC | CONFIDENTIAL)")
        ClientType type,

        /** Public + PKCE is the recommended SPA flow. Defaults to false when null. */
        Boolean pkce,

        /** Empty for service-account-only clients. */
        List<@NotBlank String> redirectUris,

        /** Web origins for CORS. Use {@code "+"} to allow all redirect-URI hosts. */
        List<@NotBlank String> webOrigins,

        Boolean serviceAccountsEnabled,

        /**
         * Name of the environment variable holding this client's secret — the
         * name, never the secret. Same rule as the identity-provider fields:
         * a manifest is a document that gets logged, diffed and stored.
         *
         * <p>Only meaningful for a CONFIDENTIAL client. Without it Keycloak
         * generates a secret nobody can predict, which is exactly the problem:
         * the service that needs it has no way to learn it, so every
         * client_credentials call comes back 401 and the failure reads like a
         * broken credential rather than one that was never handed over.
         */
        String secretEnvRef,

        /**
         * Enables the OAuth2 password (ROPC) grant. Defaults to false when
         * null, and that default should stand for almost every client — the
         * browser-redirect flow is the one to reach for.
         *
         * <p>The exception is a frontend whose login form posts to IAM's
         * {@code /public/users/login}: that endpoint exchanges the
         * credentials for tokens with exactly this grant, so a client
         * serving such a frontend has to opt in or every login returns
         * {@code unauthorized_client}.
         */
        Boolean directAccessGrantsEnabled,

        /** Realm-level roles bound to the service account. Null for public clients. */
        List<@NotBlank String> serviceAccountRoles,

        @Valid
        List<ProtocolMapperDeclaration> protocolMappers
) {
}
