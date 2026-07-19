package zm.iam.keycloak.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Caches a Keycloak admin {@code access_token} obtained via
 * {@code client_credentials} grant. Refreshes the token once the remaining
 * lifetime drops below {@code refreshLeadSeconds}. All callers see the same
 * cached token until refresh time; when refresh is due, exactly ONE thread
 * hits the token endpoint while every other caller blocks on the same lock
 * and re-uses the freshly-fetched token (single-flight).
 *
 * <p>Retries transient failures (connection refuse / 5xx) with exponential
 * backoff — production Keycloak restarts should not surface to callers.
 *
 * <p>Not a Spring bean by itself; wired through
 * {@link zm.iam.keycloak.KeycloakAdminClientProvider} which owns
 * the props + a shared HttpClient.
 */
@Slf4j
public class TokenCache {

    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final int refreshLeadSeconds;
    private final int maxAttempts;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final Supplier<Long> backoffSleeperMillis;

    private final ReentrantLock refreshLock = new ReentrantLock();

    private volatile CachedToken current;

    public TokenCache(String tokenEndpoint,
                      String clientId,
                      String clientSecret,
                      int refreshLeadSeconds,
                      int maxAttempts,
                      HttpClient httpClient,
                      ObjectMapper objectMapper,
                      Clock clock) {
        this(tokenEndpoint, clientId, clientSecret, refreshLeadSeconds, maxAttempts,
                httpClient, objectMapper, clock, TokenCache::defaultSleep);
    }

    /** Package-visible constructor for tests to inject a no-op sleep supplier
     *  and skip real wall-clock waits during backoff. */
    TokenCache(String tokenEndpoint,
               String clientId,
               String clientSecret,
               int refreshLeadSeconds,
               int maxAttempts,
               HttpClient httpClient,
               ObjectMapper objectMapper,
               Clock clock,
               Supplier<Long> backoffSleeperMillis) {
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.refreshLeadSeconds = refreshLeadSeconds;
        this.maxAttempts = maxAttempts;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.backoffSleeperMillis = backoffSleeperMillis;
    }

    /**
     * Returns a valid access token, refreshing under lock if necessary.
     * Blocks the calling thread if another thread is currently refreshing.
     */
    public String getValidToken() {
        CachedToken snapshot = current;
        if (snapshot != null && !isExpiringSoon(snapshot)) {
            return snapshot.accessToken;
        }

        refreshLock.lock();
        try {
            // Re-check under lock: while we were waiting, another thread may
            // have already refreshed. This is the single-flight guarantee.
            CachedToken postLock = current;
            if (postLock != null && !isExpiringSoon(postLock)) {
                return postLock.accessToken;
            }
            CachedToken fresh = fetchWithBackoff();
            current = fresh;
            return fresh.accessToken;
        } finally {
            refreshLock.unlock();
        }
    }

    private boolean isExpiringSoon(CachedToken token) {
        return Instant.now(clock).plusSeconds(refreshLeadSeconds).isAfter(token.expiresAt);
    }

    private CachedToken fetchWithBackoff() {
        long backoffMs = 1000L;
        RuntimeException lastError = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return fetchOnce();
            } catch (TransientTokenException e) {
                lastError = e;
                if (attempt == maxAttempts) break;
                log.warn("[TokenCache] Attempt {}/{} to fetch admin token failed transiently: {}; retrying in {}ms",
                        attempt, maxAttempts, e.getMessage(), backoffMs);
                sleep(backoffMs);
                backoffMs *= 2;
            }
        }
        throw new IllegalStateException(
                "Failed to obtain Keycloak admin token after " + maxAttempts + " attempts", lastError);
    }

    private CachedToken fetchOnce() {
        String body = "grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException ioe) {
            throw new TransientTokenException("Connection failure calling token endpoint: " + ioe.getMessage(), ioe);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while fetching admin token", ie);
        }

        int status = response.statusCode();
        if (status >= 500) {
            throw new TransientTokenException("Token endpoint returned " + status);
        }
        if (status != 200) {
            // 4xx — bad credentials, misconfigured client, etc. Non-retryable.
            throw new IllegalStateException(
                    "Token endpoint returned " + status + " (non-retryable). Body snippet: "
                            + safeSnippet(response.body()));
        }

        TokenResponse parsed;
        try {
            parsed = objectMapper.readValue(response.body(), TokenResponse.class);
        } catch (IOException e) {
            throw new IllegalStateException("Could not parse token response as JSON", e);
        }
        if (parsed.accessToken == null || parsed.accessToken.isBlank()) {
            throw new IllegalStateException("Token endpoint returned OK but no access_token in body");
        }

        Instant expiresAt = Instant.now(clock).plusSeconds(parsed.expiresIn);
        log.debug("[TokenCache] Fetched fresh admin token, expiresIn={}s", parsed.expiresIn);
        return new CachedToken(parsed.accessToken, expiresAt);
    }

    private void sleep(long millis) {
        Long overrideMs = backoffSleeperMillis.get();
        long effective = overrideMs != null ? overrideMs : millis;
        if (effective <= 0) return;
        try {
            Thread.sleep(effective);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Long defaultSleep() {
        return null; // signals "use natural backoff"
    }

    /** Truncated to avoid dumping full Keycloak error responses (may contain
     *  configured clientId) into every stack trace. */
    private static String safeSnippet(String s) {
        if (s == null) return "<null>";
        return s.length() > 200 ? s.substring(0, 200) + "…" : s;
    }

    /** Immutable snapshot of a fetched token + its expiry (walltime). */
    private record CachedToken(String accessToken, Instant expiresAt) {}

    /** Marker for "safe to retry after backoff" failures. */
    private static class TransientTokenException extends RuntimeException {
        TransientTokenException(String msg) { super(msg); }
        TransientTokenException(String msg, Throwable cause) { super(msg, cause); }
    }

    /** Subset of Keycloak's token response we care about. */
    static class TokenResponse {
        @JsonProperty("access_token")
        public String accessToken;
        @JsonProperty("expires_in")
        public long expiresIn;
    }
}
