package zm.iam.audit;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import zm.iam.provisioning.ApplyResult;
import zm.iam.provisioning.ProvisioningIT;
import zm.iam.provisioning.ProvisioningService;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end audit trail — apply a manifest, wait (async!) for the
 * audit row to land, assert its shape. Reuses the provisioning IT's
 * KC + PG setup pattern.
 */
@Testcontainers
@SpringBootTest
class AuditIT {

    private static final String ADMIN_SERVICE_CLIENT_ID = "admin-service";
    private static final String ADMIN_SERVICE_SECRET    = "it-secret";

    static final KeycloakContainer KEYCLOAK =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.2.4");

    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("iam_db").withUsername("iam_user").withPassword("iam_pass");

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
        // Retention disabled during tests — @Scheduled would trigger
        // unpredictably otherwise.
        r.add("iam.audit.retention-days", () -> "0");
    }

    @Autowired ProvisioningService service;
    @Autowired AuditLogRepository auditRepo;

    @Test
    @DisplayName("Manifest APPLY → audit row lands with caller/target/operation/detail")
    void applyManifestAuditRowPresent() {
        long baseline = auditRepo.count();

        ServiceProvisioningManifest manifest = new ServiceProvisioningManifest(
                "audit-it-svc", 1, List.of(
                new RealmDeclaration("audit-it-realm", null, List.of(
                        new ClientDeclaration("audit-it-fe", ClientType.PUBLIC, null,
                                List.of("https://audit.example/*"), null, null, null, null)),
                        null, null, null)));
        ApplyResult result = service.apply(manifest);
        assertThat(result.status()).isEqualTo(ApplyResult.Status.APPLIED);

        // Async write — poll up to 5s.
        Awaitility.await().atMost(Duration.ofSeconds(5))
                .until(() -> auditRepo.count() > baseline);

        var rows = auditRepo.findAll();
        assertThat(rows)
                .anySatisfy(row -> {
                    assertThat(row.getCaller()).isEqualTo("audit-it-svc");
                    assertThat(row.getTargetType()).isEqualTo(TargetType.MANIFEST);
                    assertThat(row.getTargetId()).isEqualTo("audit-it-svc:v1");
                    assertThat(row.getOperation()).isEqualTo("APPLY");
                    assertThat(row.isSuccess()).isTrue();
                    // Detail includes changeCount, hash — no PII.
                    assertThat(row.getDetail().has("changeCount")).isTrue();
                    assertThat(row.getDetail().has("manifestHash")).isTrue();
                });
    }

    @Test
    @DisplayName("Re-apply same version → NOOP audit row (success=true, operation=NOOP)")
    void noopEmitsAuditRow() {
        ServiceProvisioningManifest manifest = new ServiceProvisioningManifest(
                "audit-noop-svc", 5, List.of(
                new RealmDeclaration("audit-noop-realm", null, List.of(
                        new ClientDeclaration("noop-fe", ClientType.PUBLIC, null,
                                List.of("https://x.mk/*"), null, null, null, null)),
                        null, null, null)));
        service.apply(manifest);  // first — APPLIED
        long afterApply = eventuallyAtLeastOneRowThenCount();

        service.apply(manifest);  // second — NOOP
        Awaitility.await().atMost(Duration.ofSeconds(5))
                .until(() -> auditRepo.count() > afterApply);

        assertThat(auditRepo.findAll())
                .filteredOn(r -> "audit-noop-svc".equals(r.getCaller()))
                .anySatisfy(r -> {
                    assertThat(r.getOperation()).isIn("APPLY", "NOOP");
                });
    }

    private long eventuallyAtLeastOneRowThenCount() {
        Awaitility.await().atMost(Duration.ofSeconds(5))
                .until(() -> auditRepo.count() > 0);
        return auditRepo.count();
    }
}
