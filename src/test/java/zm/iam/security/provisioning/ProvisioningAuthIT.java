package zm.iam.security.provisioning;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end HTTP tests for IAM-05's filter. Uses a controllable
 * TokenRegistry so we can register real argon2 hashes at test time
 * without hitting real env vars.
 *
 * <p>Keycloak is stubbed via `iam.provisioning.security-enabled`
 * NEVER — the filter always runs. When we want the manifest to reach
 * the controller we set the filter's target service to accept the
 * incoming manifest's serviceId; for negative cases we skip Keycloak
 * because the filter short-circuits BEFORE any downstream code runs.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class ProvisioningAuthIT {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("iam_db").withUsername("iam_user").withPassword("iam_pass");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
        // No real Keycloak — the filter tests never reach a scenario
        // where downstream code runs, so dummy props suffice.
        r.add("iam.keycloak.base-url", () -> "http://localhost:1");
        r.add("iam.keycloak.admin-client-id", () -> "dummy");
        r.add("iam.keycloak.admin-client-secret", () -> "dummy");
        r.add("iam.keycloak.self-bootstrap-enabled", () -> "false");
    }

    @Autowired MockMvc mockMvc;
    @Autowired TokenRegistry tokenRegistry;
    @Autowired ProvisioningRateLimiter rateLimiter;

    private static final Argon2PasswordEncoder ARGON2 =
            Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    private static final String PLAINTEXT = "test-plaintext-token-value";
    private static String hash;

    @BeforeEach
    void seedTokens() {
        if (hash == null) hash = ARGON2.encode(PLAINTEXT);
        tokenRegistry.setHashesFor("ivy-events-be", List.of(hash));
        tokenRegistry.setHashesFor("presmetko-be", List.of(ARGON2.encode("other-token")));
        rateLimiter.reset();
    }

    private static final String VALID_BODY = """
            {
              "serviceId": "ivy-events-be",
              "manifestVersion": 1,
              "realms": [
                { "name": "auth-test",
                  "clients": [ { "clientId": "svc-fe", "type": "PUBLIC" } ] }
              ]
            }
            """;

    @Test
    @DisplayName("AC 1 — no header → 401")
    void missingHeaderIs401() throws Exception {
        mockMvc.perform(post("/provisioning/manifests")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("AC 1 — wrong token → 401")
    void wrongTokenIs401() throws Exception {
        mockMvc.perform(post("/provisioning/manifests")
                        .header(ProvisioningAuthenticationFilter.HEADER, "wrong")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("AC 3 — token for service A but body targets service B → 403; downstream untouched")
    void serviceIdMismatchIs403() throws Exception {
        String mismatchedBody = VALID_BODY.replace("ivy-events-be", "presmetko-be");
        mockMvc.perform(post("/provisioning/manifests")
                        .header(ProvisioningAuthenticationFilter.HEADER, PLAINTEXT)  // matches ivy-events-be
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mismatchedBody))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("AC 5 — rotation: two hashes → both plaintext tokens work")
    void rotationBothHashesAccepted() throws Exception {
        String secondPlaintext = "second-rotation-token";
        String secondHash = ARGON2.encode(secondPlaintext);
        tokenRegistry.setHashesFor("ivy-events-be", List.of(hash, secondHash));

        // Old token still works — expected 500/whatever from downstream
        // because Keycloak stubs won't actually apply, but the FILTER let
        // it through (status != 401/403).
        int oldStatus = mockMvc.perform(post("/provisioning/manifests")
                        .header(ProvisioningAuthenticationFilter.HEADER, PLAINTEXT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andReturn().getResponse().getStatus();
        int newStatus = mockMvc.perform(post("/provisioning/manifests")
                        .header(ProvisioningAuthenticationFilter.HEADER, secondPlaintext)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andReturn().getResponse().getStatus();

        // Both must NOT be 401 (token invalid) or 403 (mismatch) — the
        // filter accepted both plaintext tokens.
        org.assertj.core.api.Assertions.assertThat(oldStatus).isNotIn(401, 403);
        org.assertj.core.api.Assertions.assertThat(newStatus).isNotIn(401, 403);
    }

    @Test
    @DisplayName("AC 4 — 11 fast failed attempts from same IP → last is 429")
    void rateLimitedAfterTenFailures() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/provisioning/manifests")
                            .header(ProvisioningAuthenticationFilter.HEADER, "bad-" + i)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(VALID_BODY))
                    .andExpect(status().isUnauthorized());
        }
        mockMvc.perform(post("/provisioning/manifests")
                        .header(ProvisioningAuthenticationFilter.HEADER, "bad-final")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(status().isTooManyRequests());
    }
}
