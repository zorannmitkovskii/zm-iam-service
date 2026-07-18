package org.ivyinc.iam.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.ivyinc.iam.keycloak.config.KeycloakProperties;
import org.ivyinc.iam.keycloak.token.TokenCache;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;

/**
 * Owns the Keycloak admin credentials and hands out authenticated
 * {@link Keycloak} clients on demand. Never exposes the raw client
 * secret, never lets callers build their own admin client.
 *
 * <p>Under the hood a {@link TokenCache} keeps a valid access token in
 * memory (refreshed 60s before expiry, single-flight); each
 * {@link #client()} call wraps the cached token in a stateless
 * {@code Keycloak.authorization(token)} builder — no per-call token
 * request unless the cache decided to refresh.
 */
@Slf4j
@Component
public class KeycloakAdminSession {

    private final KeycloakProperties props;
    private final ObjectMapper objectMapper;

    private TokenCache tokenCache;

    /** Where the admin client CONNECTS to Keycloak. Almost always same as
     *  props.baseUrl, but split out so tests can override. */
    private String effectiveServerUrl;

    public KeycloakAdminSession(KeycloakProperties props, ObjectMapper objectMapper) {
        this.props = props;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    void init() {
        if (!StringUtils.hasText(props.getBaseUrl())) {
            throw new IllegalStateException(
                    "iam.keycloak.base-url (env KEYCLOAK_BASE_URL) must be configured");
        }
        if (!StringUtils.hasText(props.getAdminClientId()) ||
                !StringUtils.hasText(props.getAdminClientSecret())) {
            throw new IllegalStateException(
                    "iam.keycloak.admin-client-id + admin-client-secret must be configured "
                            + "(envs KEYCLOAK_ADMIN_CLIENT_ID / KEYCLOAK_ADMIN_CLIENT_SECRET)");
        }

        this.effectiveServerUrl = trimTrailingSlash(props.getBaseUrl());
        String tokenEndpoint = effectiveServerUrl
                + "/realms/" + props.getAdminRealm()
                + "/protocol/openid-connect/token";

        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        this.tokenCache = new TokenCache(
                tokenEndpoint,
                props.getAdminClientId(),
                props.getAdminClientSecret(),
                props.getTokenRefreshLeadSeconds(),
                props.getTokenFetchMaxAttempts(),
                httpClient,
                objectMapper,
                Clock.systemUTC()
        );

        // Log presence, never the value. clientId length included since a
        // subtle trailing-whitespace bug once left us wondering why
        // Keycloak returned client_not_found for `admin-service`.
        log.info("[KeycloakAdminSession] Configured — serverUrl={}, adminRealm={}, "
                        + "clientId='{}' (len={}), secretPresent={}",
                effectiveServerUrl,
                props.getAdminRealm(),
                props.getAdminClientId(),
                props.getAdminClientId().length(),
                StringUtils.hasText(props.getAdminClientSecret()));
    }

    /** Returns a Keycloak admin client authenticated with a cached admin
     *  token. Safe to call from any thread; may block briefly on refresh.
     *  Caller is expected to use try-with-resources — the returned client
     *  is {@link AutoCloseable}. */
    public Keycloak client() {
        String token = tokenCache.getValidToken();
        return KeycloakBuilder.builder()
                .serverUrl(effectiveServerUrl)
                .realm(props.getAdminRealm())
                .authorization(token)
                .build();
    }

    /** Test/observability hook — exposes token cache so a probe or an
     *  integration test can force a refresh check. NOT wired to any
     *  external endpoint. */
    TokenCache getTokenCache() {
        return tokenCache;
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
