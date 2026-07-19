package org.ivyinc.iam.provisioning.dto;

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

        /** Realm-level roles bound to the service account. Null for public clients. */
        List<@NotBlank String> serviceAccountRoles,

        @Valid
        List<ProtocolMapperDeclaration> protocolMappers
) {
}
