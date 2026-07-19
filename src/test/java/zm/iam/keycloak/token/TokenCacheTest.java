package zm.iam.keycloak.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * TokenCache behaviour tests. Uses WireMock to expose a real HTTP endpoint
 * that counts requests — the only way to verify single-flight + cache-hit
 * semantics without a shim inside TokenCache itself.
 *
 * <p>Time is controlled via {@link MutableClock} so we can jump 60s at a
 * time without wall-clock waits.
 */
class TokenCacheTest {

    private static final String TOKEN_PATH = "/realms/master/protocol/openid-connect/token";

    private WireMockServer wm;
    private String endpoint;
    private HttpClient httpClient;
    private ObjectMapper mapper;

    @BeforeEach
    void startWireMock() {
        wm = new WireMockServer(wireMockConfig().dynamicPort());
        wm.start();
        endpoint = "http://localhost:" + wm.port() + TOKEN_PATH;
        httpClient = HttpClient.newHttpClient();
        mapper = new ObjectMapper();
    }

    @AfterEach
    void stopWireMock() {
        wm.stop();
    }

    // ── Cache hit ──────────────────────────────────────────────────

    @Test
    @DisplayName("Sequential callers within cache window → exactly ONE token endpoint hit")
    void sequentialCallersReuseCachedToken() {
        stubToken("cached-abc", 300);
        TokenCache cache = newCache(fixedClock(), /*refreshLead*/ 60, /*maxAttempts*/ 5);

        for (int i = 0; i < 10; i++) {
            assertThat(cache.getValidToken()).isEqualTo("cached-abc");
        }

        wm.verify(1, postRequestedFor(urlPathEqualTo(TOKEN_PATH)));
    }

    // ── Single-flight ──────────────────────────────────────────────

    @Test
    @DisplayName("N parallel callers on cold cache → exactly ONE token endpoint hit (single-flight)")
    void parallelCallersOnColdCacheProduceExactlyOneFetch() throws Exception {
        // Delay the response by 300ms so parallel threads have time to
        // pile up on the refresh lock before the first fetch resolves.
        wm.stubFor(post(urlPathEqualTo(TOKEN_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withFixedDelay(300)
                        .withBody("{\"access_token\":\"single-flight-token\",\"expires_in\":300}")));

        TokenCache cache = newCache(fixedClock(), 60, 5);

        int callers = 10;
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        CountDownLatch releaseGate = new CountDownLatch(1);
        List<Future<String>> results = new ArrayList<>();
        try {
            for (int i = 0; i < callers; i++) {
                results.add(pool.submit(() -> {
                    releaseGate.await();
                    return cache.getValidToken();
                }));
            }
            releaseGate.countDown();
            for (Future<String> f : results) {
                assertThat(f.get(5, TimeUnit.SECONDS)).isEqualTo("single-flight-token");
            }
        } finally {
            pool.shutdownNow();
        }
        wm.verify(1, postRequestedFor(urlPathEqualTo(TOKEN_PATH)));
    }

    // ── Refresh timing ─────────────────────────────────────────────

    @Test
    @DisplayName("Token with 61s remaining lifetime → no refresh; 59s → refresh")
    void refreshBoundaryHonoursLeadSeconds() {
        stubToken("first-token", 121); // fresh at t=0, expires at t=121
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        TokenCache cache = newCache(clock, /*refreshLead*/ 60, 5);

        // t=0 — fetch #1
        assertThat(cache.getValidToken()).isEqualTo("first-token");
        wm.verify(1, postRequestedFor(urlPathEqualTo(TOKEN_PATH)));

        // t=60 → 61s until expiry → still cached (no fetch)
        clock.advanceSeconds(60);
        assertThat(cache.getValidToken()).isEqualTo("first-token");
        wm.verify(1, postRequestedFor(urlPathEqualTo(TOKEN_PATH)));

        // t=62 → 59s until expiry → should refresh
        stubToken("second-token", 300);
        clock.advanceSeconds(2);
        assertThat(cache.getValidToken()).isEqualTo("second-token");
        wm.verify(2, postRequestedFor(urlPathEqualTo(TOKEN_PATH)));
    }

    // ── Retry / backoff ────────────────────────────────────────────

    @Test
    @DisplayName("Transient 503 → retry with backoff → eventual success (no wall-clock wait)")
    void retriesOnFiveHundredThenSucceeds() {
        // First TWO calls return 503, the THIRD returns 200. Scenarios keep
        // it deterministic across the retry sequence.
        wm.stubFor(post(urlPathEqualTo(TOKEN_PATH))
                .inScenario("retry")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(503))
                .willSetStateTo("attempt-1"));
        wm.stubFor(post(urlPathEqualTo(TOKEN_PATH))
                .inScenario("retry")
                .whenScenarioStateIs("attempt-1")
                .willReturn(aResponse().withStatus(503))
                .willSetStateTo("attempt-2"));
        wm.stubFor(post(urlPathEqualTo(TOKEN_PATH))
                .inScenario("retry")
                .whenScenarioStateIs("attempt-2")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"eventually-ok\",\"expires_in\":300}")));

        // maxAttempts=5, but suppress real backoff sleep via test-only ctor.
        TokenCache cache = new TokenCache(
                endpoint, "admin-service", "secret", 60, 5,
                httpClient, mapper, fixedClock(),
                () -> 0L /* zero-ms backoff for test */);

        assertThat(cache.getValidToken()).isEqualTo("eventually-ok");
        wm.verify(3, postRequestedFor(urlPathEqualTo(TOKEN_PATH)));
    }

    @Test
    @DisplayName("Non-retryable 4xx → fails fast, never retries")
    void nonRetryableFourHundredDoesNotRetry() {
        wm.stubFor(post(urlPathEqualTo(TOKEN_PATH))
                .willReturn(aResponse()
                        .withStatus(401)
                        .withBody("{\"error\":\"invalid_client\"}")));

        TokenCache cache = new TokenCache(
                endpoint, "admin-service", "secret", 60, 5,
                httpClient, mapper, fixedClock(),
                () -> 0L);

        AtomicReference<Throwable> caught = new AtomicReference<>();
        try {
            cache.getValidToken();
        } catch (Throwable t) {
            caught.set(t);
        }
        assertThat(caught.get()).isNotNull();
        wm.verify(1, postRequestedFor(urlPathEqualTo(TOKEN_PATH)));
    }

    // ── Helpers ────────────────────────────────────────────────────

    private TokenCache newCache(Clock clock, int refreshLead, int maxAttempts) {
        return new TokenCache(
                endpoint, "admin-service", "secret",
                refreshLead, maxAttempts,
                httpClient, mapper, clock);
    }

    private void stubToken(String access, long expiresIn) {
        wm.stubFor(post(urlPathEqualTo(TOKEN_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"" + access + "\",\"expires_in\":" + expiresIn + "}")));
    }

    private static Clock fixedClock() {
        return Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    }

    /** Minimal mutable clock — we advance in whole seconds to simulate the
     *  passage of time without wall-clock waits. */
    static class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant start) { this.now = start; }
        void advanceSeconds(long s) { now = now.plusSeconds(s); }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
