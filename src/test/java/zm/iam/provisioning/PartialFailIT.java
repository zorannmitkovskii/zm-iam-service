package zm.iam.provisioning;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import zm.iam.provisioning.dto.IdentityProviderDeclaration;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;
import zm.iam.provisioning.persistence.AppliedManifestRepository;
import zm.iam.provisioning.reconcile.EnvVarResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC 6 — partial-fail recovery. Uses a controllable {@link EnvVarResolver}
 * so we can simulate a missing IdP env var, verify the reconciler bails
 * BEFORE any Keycloak IdP write, verify {@code applied_manifests} was NOT
 * persisted (@Transactional rollback), then set the env var and verify
 * the same version applies cleanly on retry.
 */
@Testcontainers
@SpringBootTest(classes = { zm.iam.IvyIamApplication.class, PartialFailIT.TestEnv.class })
class PartialFailIT {

    private static final String ADMIN_SERVICE_CLIENT_ID = "admin-service";
    private static final String ADMIN_SERVICE_SECRET    = "it-secret";

    static final KeycloakContainer KEYCLOAK =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.2.4");

    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("iam_db")
                    .withUsername("iam_user")
                    .withPassword("iam_pass");

    /** Controllable env — test flips values on it. */
    static final ControllableEnv ENV = new ControllableEnv();

    static {
        KEYCLOAK.start();
        POSTGRES.start();
        ProvisioningIT.seedAdminServiceClient(KEYCLOAK);
    }

    static class ControllableEnv extends EnvVarResolver {
        final Map<String, String> values = new HashMap<>();
        @Override public String get(String name) { return values.get(name); }
    }

    static class TestEnv {
        @Bean @Primary EnvVarResolver envVarResolver() { return ENV; }
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
        r.add("iam.keycloak.base-url", KEYCLOAK::getAuthServerUrl);
        r.add("iam.keycloak.admin-client-id", () -> ADMIN_SERVICE_CLIENT_ID);
        r.add("iam.keycloak.admin-client-secret", () -> ADMIN_SERVICE_SECRET);
        r.add("iam.keycloak.admin-realm", () -> "master");
        r.add("iam.keycloak.self-bootstrap-enabled", () -> "true");
        // TestEnv @Bean overrides the @Component EnvVarResolver — Spring
        // Boot 2.1+ blocks overrides by default.
        r.add("spring.main.allow-bean-definition-overriding", () -> "true");
    }

    @Autowired ProvisioningService service;
    @Autowired AppliedManifestRepository repository;

    @Test
    @DisplayName("Missing env var → 500-shaped exception, applied_manifests row NOT written, retry after fix succeeds")
    void missingEnvVarThenRecovery() {
        String serviceId = "partial-fail-svc";
        ENV.values.clear();  // ensure both env vars missing

        ServiceProvisioningManifest manifest = manifest(serviceId, 1);

        assertThatThrownBy(() -> service.apply(manifest))
                .isInstanceOf(ProvisioningFailedException.class)
                .hasMessageContaining("PARTIAL_FAIL_GOOGLE_ID");

        // AC 6: no applied_manifests row for this version yet.
        assertThat(repository.findFirstByServiceIdOrderByVersionDesc(serviceId)).isEmpty();

        // Set the env vars → retry SAME version → succeeds.
        ENV.values.put("PARTIAL_FAIL_GOOGLE_ID", "the-client-id");
        ENV.values.put("PARTIAL_FAIL_GOOGLE_SECRET", "the-secret");

        ApplyResult retry = service.apply(manifest);
        assertThat(retry.status()).isEqualTo(ApplyResult.Status.APPLIED);
        assertThat(retry.appliedVersion()).isEqualTo(1);
        assertThat(repository.findFirstByServiceIdOrderByVersionDesc(serviceId)).isPresent();
    }

    private static ServiceProvisioningManifest manifest(String serviceId, int version) {
        RealmDeclaration realm = new RealmDeclaration(
                "partial-fail-realm-" + serviceId,
                null, null, null,
                List.of(new IdentityProviderDeclaration(
                        "google", "GOOGLE", "PARTIAL_FAIL_GOOGLE_ID", "PARTIAL_FAIL_GOOGLE_SECRET")),
                null);
        return new ServiceProvisioningManifest(serviceId, version, List.of(realm));
    }
}
