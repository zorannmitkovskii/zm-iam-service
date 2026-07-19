package zm.iam.provisioning;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end for {@code POST /provisioning/manifests/validate}. Uses a
 * real Postgres + real Spring context so we exercise the full parser +
 * validator + hasher wiring, plus GlobalExceptionHandler's 400 shape.
 *
 * <p>Keycloak is stubbed (no live container) via dummy props +
 * self-bootstrap disabled — validate is a dry-run endpoint, it never
 * talks to Keycloak.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class ManifestControllerIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("iam_db")
            .withUsername("iam_user")
            .withPassword("iam_pass");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);

        // Keycloak stubs — validate endpoint doesn't touch Keycloak.
        registry.add("iam.keycloak.base-url", () -> "http://localhost:1");
        registry.add("iam.keycloak.admin-client-id", () -> "dummy");
        registry.add("iam.keycloak.admin-client-secret", () -> "dummy");
        registry.add("iam.keycloak.self-bootstrap-enabled", () -> "false");
    }

    @Autowired MockMvc mockMvc;

    @Test
    @DisplayName("Valid JSON manifest → 200 with hash")
    void validJsonManifestReturnsHash() throws Exception {
        String body = """
                {
                  "serviceId": "svc",
                  "manifestVersion": 1,
                  "realms": [
                    { "name": "app",
                      "clients": [ { "clientId": "app-frontend", "type": "PUBLIC" } ] }
                  ]
                }
                """;
        mockMvc.perform(post("/provisioning/manifests/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.valid").value(true))
                .andExpect(jsonPath("$.data.hash").isString())
                .andExpect(jsonPath("$.data.serviceId").value("svc"));
    }

    @Test
    @DisplayName("Valid YAML manifest → 200 with hash")
    void validYamlManifestReturnsHash() throws Exception {
        String body = """
                serviceId: svc
                manifestVersion: 1
                realms:
                  - name: app
                    clients:
                      - clientId: app-frontend
                        type: PUBLIC
                """;
        mockMvc.perform(post("/provisioning/manifests/validate")
                        .contentType(MediaType.parseMediaType("application/yaml"))
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.hash").isString());
    }

    @Test
    @DisplayName("Invalid manifest → 400 with per-field errors")
    void invalidManifestReturnsFieldErrors() throws Exception {
        String body = """
                {
                  "serviceId": "Bad Service ID",
                  "manifestVersion": 0,
                  "realms": []
                }
                """;
        mockMvc.perform(post("/provisioning/manifests/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.data.fieldErrors").isArray())
                // Multiple violations → multiple entries
                .andExpect(jsonPath("$.data.fieldErrors[*].field").isNotEmpty());
    }

    @Test
    @DisplayName("Plaintext IdP secret → 400 (unknown property)")
    void plaintextIdpSecretRejected() throws Exception {
        String body = """
                {
                  "serviceId": "svc",
                  "manifestVersion": 1,
                  "realms": [
                    { "name": "app",
                      "identityProviders": [
                        { "alias": "google", "type": "GOOGLE",
                          "clientIdEnvRef": "MY_ID",
                          "clientSecretEnvRef": "MY_SECRET",
                          "clientSecret": "leaked" }
                      ]
                    }
                  ]
                }
                """;
        mockMvc.perform(post("/provisioning/manifests/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.detail").value(org.hamcrest.Matchers.containsString("clientSecret")));
    }

    @Test
    @DisplayName("Foreign client in zm-services → 400 with zmServicesScopeRespected error")
    void zmServicesForeignClientRejected() throws Exception {
        String body = """
                {
                  "serviceId": "ivy-events-be",
                  "manifestVersion": 1,
                  "realms": [
                    { "name": "zm-services",
                      "clients": [ { "clientId": "evil-client", "type": "CONFIDENTIAL" } ] }
                  ]
                }
                """;
        mockMvc.perform(post("/provisioning/manifests/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.fieldErrors[*].field")
                        .value(org.hamcrest.Matchers.hasItem("zmServicesScopeRespected")));
    }
}
