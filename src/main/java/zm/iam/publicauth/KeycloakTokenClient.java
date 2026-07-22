package zm.iam.publicauth;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import zm.iam.keycloak.config.KeycloakProperties;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * Direct HTTP client for Keycloak's OpenID Connect token endpoint —
 * password grant + refresh_token grant. Not on the admin API surface,
 * so it lives outside {@link zm.iam.keycloak.KeycloakAdminApi} which is
 * for admin operations (create realm, create user, etc).
 *
 * <p>Uses the {@code frontend-public-client} in each realm (assumed to
 * exist with direct-access-grants enabled). The client id per realm is
 * configurable via {@link Configurable#getRealmClientIds()} — Ivy today
 * uses {@code eventFE} for {@code event-app}.
 */
@Slf4j
@Component
public class KeycloakTokenClient {

    private final KeycloakProperties keycloakProps;
    private final Configurable config;
    private final ObjectMapper mapper;
    private HttpClient httpClient;

    public KeycloakTokenClient(KeycloakProperties keycloakProps,
                                Configurable config,
                                ObjectMapper mapper) {
        this.keycloakProps = keycloakProps;
        this.config = config;
        this.mapper = mapper;
    }

    @PostConstruct
    void init() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public TokenResponse passwordGrant(String realm, String username, String password) {
        String clientId = clientIdFor(realm);
        String body = "grant_type=password"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8)
                + "&scope=openid";
        return post(realm, body);
    }

    public TokenResponse refreshToken(String realm, String refreshToken) {
        String clientId = clientIdFor(realm);
        String body = "grant_type=refresh_token"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&refresh_token=" + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8);
        return post(realm, body);
    }

    private TokenResponse post(String realm, String body) {
        String url = trimTrailingSlash(keycloakProps.getBaseUrl())
                + "/realms/" + realm + "/protocol/openid-connect/token";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new PasswordGrantException("Network failure calling Keycloak token endpoint: " + e.getMessage(), 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PasswordGrantException("Interrupted calling Keycloak token endpoint", 0);
        }
        if (resp.statusCode() != 200) {
            throw new PasswordGrantException(
                    "Keycloak token endpoint returned " + resp.statusCode() + " body=" + snippet(resp.body()),
                    resp.statusCode());
        }
        try {
            return mapper.readValue(resp.body(), TokenResponse.class);
        } catch (IOException e) {
            throw new PasswordGrantException("Could not parse token response", 200);
        }
    }

    private String clientIdFor(String realm) {
        String id = config.getRealmClientIds().get(realm);
        if (id == null) {
            throw new IllegalStateException(
                    "No public client id configured for realm '" + realm
                            + "'. Add iam.public-auth.realm-client-ids." + realm + "=... to application.yml");
        }
        return id;
    }

    private static String snippet(String s) {
        if (s == null) return "";
        return s.length() > 200 ? s.substring(0, 200) + "…" : s;
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** {@link Map} of realm → public client id. Bound to
     *  {@code iam.public-auth.realm-client-ids}. */
    @lombok.Getter
    @lombok.Setter
    @org.springframework.boot.context.properties.ConfigurationProperties(prefix = "iam.public-auth")
    @Component
    public static class Configurable {
        private Map<String, String> realmClientIds = new java.util.HashMap<>();
    }

    /** Slim view of the OIDC token response. Ignores unknown fields
     *  because Keycloak's payload includes plenty we don't need. */
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("id_token") String idToken,
            @JsonProperty("expires_in") long expiresIn,
            @JsonProperty("refresh_expires_in") long refreshExpiresIn,
            @JsonProperty("token_type") String tokenType
    ) {}

    /** Thrown on any non-200 from the token endpoint (usually 401
     *  invalid credentials). */
    public static class PasswordGrantException extends RuntimeException {
        @lombok.Getter private final int status;
        public PasswordGrantException(String msg, int status) { super(msg); this.status = status; }
    }
}
