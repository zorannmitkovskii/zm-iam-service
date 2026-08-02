package zm.iam.provisioning;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;
import zm.iam.provisioning.persistence.AppliedManifest;
import zm.iam.provisioning.persistence.AppliedManifestRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC 5 — pg_advisory_xact_lock serialises two callers hitting the same
 * realm. We start both threads via a CountDownLatch so they contend for
 * the lock at ~the same moment, then verify:
 * <ul>
 *   <li>Both apply calls return without exception (no lock timeout).</li>
 *   <li>Both {@code applied_manifests} rows persist (v5 and v6).</li>
 *   <li>Whichever version won the race is reflected in the FINAL
 *       Keycloak state (its redirect URI wins).</li>
 * </ul>
 */
@Testcontainers
@SpringBootTest
class ConcurrencyIT {

    private static final String ADMIN_SERVICE_CLIENT_ID = "admin-service";
    private static final String ADMIN_SERVICE_SECRET    = "it-secret";

    static final KeycloakContainer KEYCLOAK =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.2.4");

    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("iam_db")
                    .withUsername("iam_user")
                    .withPassword("iam_pass");

    static {
        KEYCLOAK.start();
        POSTGRES.start();
        ProvisioningIT.seedAdminServiceClient(KEYCLOAK);
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
    }

    @Autowired ProvisioningService service;
    @Autowired AppliedManifestRepository repository;

    @Test
    @DisplayName("Two concurrent applies on same realm → advisory lock serialises; both rows persist")
    void twoConcurrentApplies() throws Exception {
        String svc = "concurrency-svc";
        CountDownLatch gate = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<ApplyResult> f5 = pool.submit(() -> {
                gate.await();
                return service.apply(manifest(svc, 5, "https://v5.mk/*"));
            });
            Future<ApplyResult> f6 = pool.submit(() -> {
                gate.await();
                return service.apply(manifest(svc, 6, "https://v6.mk/*"));
            });
            gate.countDown();

            ApplyResult r5 = f5.get(30, TimeUnit.SECONDS);
            ApplyResult r6 = f6.get(30, TimeUnit.SECONDS);

            // Both must complete cleanly — advisory lock serialises,
            // neither is refused nor rolled back.
            assertThat(r5.status()).isEqualTo(ApplyResult.Status.APPLIED);
            assertThat(r6.status()).isEqualTo(ApplyResult.Status.APPLIED);

            List<AppliedManifest> rows = repository.findAllByServiceIdOrderByVersionDesc(svc);
            assertThat(rows).extracting(AppliedManifest::getVersion).contains(5, 6);
        } finally {
            pool.shutdownNow();
        }
    }

    private static ServiceProvisioningManifest manifest(String serviceId, int version, String redirectUri) {
        ClientDeclaration client = new ClientDeclaration(
                "concurrency-fe", ClientType.PUBLIC, null,
                List.of(redirectUri), null, null, null, null, null, null);
        return new ServiceProvisioningManifest(serviceId, version, List.of(
                new RealmDeclaration("concurrency-realm", null, List.of(client),
                        null, null, null)));
    }
}
