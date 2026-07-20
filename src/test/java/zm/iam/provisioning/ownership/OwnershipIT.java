package zm.iam.provisioning.ownership;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import zm.iam.keycloak.KeycloakAdminSession;
import zm.iam.provisioning.ApplyResult;
import zm.iam.provisioning.ProvisioningIT;
import zm.iam.provisioning.ProvisioningService;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end for IAM-06: two services on the same Keycloak, ownership
 * enforced across them. Uses a real Keycloak container so the "Keycloak
 * untouched on conflict" assertion is meaningful.
 */
@Testcontainers
@SpringBootTest
class OwnershipIT {

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
    }

    @Autowired ProvisioningService service;
    @Autowired ResourceOwnershipRepository ownershipRepo;
    @Autowired KeycloakAdminSession session;

    @Test
    @DisplayName("Two services on separate realms → both APPLIED, ownership rows planted")
    void twoServicesTwoRealms() {
        var manifestA = manifest("owner-a", 1, "realm-a-app", "clientA");
        var manifestB = manifest("owner-b", 1, "realm-b-app", "clientB");

        service.apply(manifestA);
        service.apply(manifestB);

        var ownersA = ownershipRepo.findAllByRealmOrderByResourceTypeAscResourceNameAsc("realm-a-app");
        var ownersB = ownershipRepo.findAllByRealmOrderByResourceTypeAscResourceNameAsc("realm-b-app");
        assertThat(ownersA).extracting(ResourceOwnership::getOwnerService).containsOnly("owner-a");
        assertThat(ownersB).extracting(ResourceOwnership::getOwnerService).containsOnly("owner-b");
    }

    @Test
    @DisplayName("Cross-service conflict → 409 (OwnershipConflictException), Keycloak untouched")
    void crossServiceConflictLeavesKeycloakUntouched() {
        var manifestA = manifest("cross-a", 1, "shared-realm", "app-fe");
        service.apply(manifestA);

        // Confirm Keycloak state BEFORE the conflicting apply.
        String initialClientUuid;
        try (Keycloak admin = session.client()) {
            initialClientUuid = admin.realm("shared-realm").clients()
                    .findByClientId("app-fe").get(0).getId();
        }

        // Now service B tries to squat on the same realm.
        var manifestB = manifest("cross-b", 1, "shared-realm", "app-fe");
        assertThatThrownBy(() -> service.apply(manifestB))
                .isInstanceOf(OwnershipConflictException.class)
                .satisfies(ex -> {
                    var conflicts = ((OwnershipConflictException) ex).getConflicts();
                    assertThat(conflicts).isNotEmpty();
                    assertThat(conflicts).extracting(OwnershipConflict::ownerService)
                            .contains("cross-a");
                });

        // Keycloak state should be IDENTICAL — same client UUID means no
        // recreate/update happened.
        try (Keycloak admin = session.client()) {
            String uuidAfter = admin.realm("shared-realm").clients()
                    .findByClientId("app-fe").get(0).getId();
            assertThat(uuidAfter).isEqualTo(initialClientUuid);
        }
    }

    @Test
    @DisplayName("zm-services: any service may create its own {serviceId}-svc client")
    void zmServicesPerServiceClientAllowed() {
        var manifest = new ServiceProvisioningManifest("zm-a-svc-owner", 1, List.of(
                new RealmDeclaration("zm-a-svc-owner-realm", null, null, null, null, null),
                new RealmDeclaration("zm-services", null,
                        List.of(new ClientDeclaration("zm-a-svc-owner-svc",
                                ClientType.CONFIDENTIAL, null, null, null, true,
                                List.of("iam-client"), null)),
                        null, null, null)));

        ApplyResult result = service.apply(manifest);
        assertThat(result.status()).isEqualTo(ApplyResult.Status.APPLIED);

        // The zm-services realm itself is IAM-owned (planted by
        // ServiceRealmProvisioner). The svc client is owned by us.
        var svcClientOwner = ownershipRepo.findByResourceTypeAndRealmAndResourceName(
                ResourceType.CLIENT, "zm-services", "zm-a-svc-owner-svc");
        assertThat(svcClientOwner).isPresent();
        assertThat(svcClientOwner.get().getOwnerService()).isEqualTo("zm-a-svc-owner");

        var realmOwner = ownershipRepo.findByResourceTypeAndRealmAndResourceName(
                ResourceType.REALM, "zm-services", "zm-services");
        assertThat(realmOwner).isPresent();
        assertThat(realmOwner.get().getOwnerService()).isEqualTo(OwnershipService.IAM_OWNER);
    }

    private static ServiceProvisioningManifest manifest(String svc, int version, String realmName, String clientId) {
        return new ServiceProvisioningManifest(svc, version, List.of(
                new RealmDeclaration(realmName, null,
                        List.of(new ClientDeclaration(clientId, ClientType.PUBLIC, null,
                                List.of("https://x.mk/*"), null, null, null, null)),
                        null, null, null)));
    }
}
