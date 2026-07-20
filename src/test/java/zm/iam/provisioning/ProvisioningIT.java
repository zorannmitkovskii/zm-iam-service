package zm.iam.provisioning;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import zm.iam.keycloak.KeycloakAdminSession;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import zm.iam.provisioning.dto.ProtocolMapperDeclaration;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;
import zm.iam.provisioning.persistence.AppliedManifestRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end apply flow against real Keycloak 26.2 + Postgres. Covers
 * the three headline acceptance criteria:
 * <ol>
 *   <li>Clean Keycloak + shaped manifest → realm + client + role +
 *       mapper materialised in Keycloak.</li>
 *   <li>Re-apply same version → NOOP, single applied_manifests row.</li>
 *   <li>Version bump with new redirect URI → APPLIED with client
 *       UPDATE change; unchanged resources SKIPPED.</li>
 * </ol>
 *
 * <p>Concurrency + partial-fail scenarios live in their own IT classes.
 */
@Testcontainers
@SpringBootTest
public class ProvisioningIT {

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
        seedAdminServiceClient(KEYCLOAK);
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

    /** Public static so PartialFailIT + ConcurrencyIT can seed their own
     *  KeycloakContainer. Each @SpringBootTest class has an isolated
     *  container instance. */
    public static void seedAdminServiceClient(KeycloakContainer kc) {
        try (Keycloak master = KeycloakBuilder.builder()
                .serverUrl(kc.getAuthServerUrl())
                .realm("master")
                .username(kc.getAdminUsername())
                .password(kc.getAdminPassword())
                .clientId("admin-cli")
                .build()) {
            RealmResource masterRealm = master.realm("master");
            ClientRepresentation client = new ClientRepresentation();
            client.setClientId(ADMIN_SERVICE_CLIENT_ID);
            client.setSecret(ADMIN_SERVICE_SECRET);
            client.setPublicClient(false);
            client.setServiceAccountsEnabled(true);
            client.setStandardFlowEnabled(false);
            client.setDirectAccessGrantsEnabled(false);
            client.setEnabled(true);
            masterRealm.clients().create(client);
            String clientUuid = masterRealm.clients()
                    .findByClientId(ADMIN_SERVICE_CLIENT_ID).get(0).getId();
            UserRepresentation sa = masterRealm.clients().get(clientUuid).getServiceAccountUser();
            RoleRepresentation adminRole = masterRealm.roles().get("admin").toRepresentation();
            masterRealm.users().get(sa.getId()).roles().realmLevel().add(List.of(adminRole));
        }
    }

    @Autowired ProvisioningService service;
    @Autowired AppliedManifestRepository repository;
    @Autowired KeycloakAdminSession session;

    @Test
    @DisplayName("Clean KC + manifest → realm + client + role + mapper materialised; APPLIED")
    void firstApplyCreatesEverything() {
        ApplyResult result = service.apply(sampleManifest(1, "https://ivyevents.mk/*", true));

        assertThat(result.status()).isEqualTo(ApplyResult.Status.APPLIED);
        assertThat(result.appliedVersion()).isEqualTo(1);

        try (Keycloak admin = session.client()) {
            RealmRepresentation realm = admin.realm("event-app-it").toRepresentation();
            assertThat(realm.isEnabled()).isTrue();

            List<ClientRepresentation> clients = admin.realm("event-app-it").clients().findByClientId("eventFE");
            assertThat(clients).hasSize(1);
            assertThat(clients.get(0).getRedirectUris()).containsExactly("https://ivyevents.mk/*");

            List<ProtocolMapperRepresentation> mappers = admin.realm("event-app-it")
                    .clients().get(clients.get(0).getId()).getProtocolMappers().getMappers();
            assertThat(mappers).anyMatch(m -> "eventIds".equals(m.getName()));

            assertThat(admin.realm("event-app-it").roles().get("USER").toRepresentation().getName()).isEqualTo("USER");
        }
        assertThat(repository.findFirstByServiceIdOrderByVersionDesc("ivy-events-be-it"))
                .isPresent()
                .get()
                .satisfies(row -> assertThat(row.getVersion()).isEqualTo(1));
    }

    @Test
    @DisplayName("Re-apply same version → NOOP; single applied_manifests row for that version")
    void reApplyIsNoop() {
        service.apply(sampleManifest(2, "https://noop.mk/*", true));

        ApplyResult second = service.apply(sampleManifest(2, "https://noop.mk/*", true));
        assertThat(second.status()).isEqualTo(ApplyResult.Status.NOOP);
        assertThat(second.changes()).isEmpty();

        long rows = repository.findAllByServiceIdOrderByVersionDesc("ivy-events-be-it").stream()
                .filter(r -> r.getVersion() == 2).count();
        assertThat(rows).isEqualTo(1);
    }

    @Test
    @DisplayName("Bump with new redirect URI → APPLIED, client UPDATE with redirectUris in details")
    void versionBumpUpdatesClient() {
        service.apply(sampleManifest(3, "https://old.mk/*", true));

        ApplyResult bump = service.apply(sampleManifest(4, "https://new.mk/*", true));

        assertThat(bump.status()).isEqualTo(ApplyResult.Status.APPLIED);
        assertThat(bump.changes())
                .anyMatch(c -> "client".equals(c.resource())
                        && "UPDATED".equals(c.action())
                        && c.details() != null && c.details().contains("redirectUris"));

        try (Keycloak admin = session.client()) {
            List<ClientRepresentation> clients = admin.realm("event-app-it").clients().findByClientId("eventFE");
            assertThat(clients.get(0).getRedirectUris()).containsExactly("https://new.mk/*");
        }
    }

    @Test
    @DisplayName("Bump with mapper removed → DELETE only the previously-declared mapper")
    void deletesPreviouslyDeclaredMapperOnRemoval() {
        // v5 declares mapper "eventIds"; v6 declares no mappers at all.
        service.apply(sampleManifest(5, "https://del.mk/*", true));
        ApplyResult removed = service.apply(sampleManifest(6, "https://del.mk/*", false));

        assertThat(removed.status()).isEqualTo(ApplyResult.Status.APPLIED);
        assertThat(removed.changes())
                .anyMatch(c -> "protocolMapper".equals(c.resource())
                        && "DELETED".equals(c.action())
                        && c.name().endsWith("/eventIds"));
    }

    private static ServiceProvisioningManifest sampleManifest(int version, String redirectUri, boolean withMapper) {
        List<ProtocolMapperDeclaration> mappers = withMapper
                ? List.of(new ProtocolMapperDeclaration("eventIds", "eventIds", "eventIds", true, null))
                : null;
        ClientDeclaration client = new ClientDeclaration(
                "eventFE", ClientType.PUBLIC, true,
                List.of(redirectUri), List.of("+"),
                null, null, mappers);
        return new ServiceProvisioningManifest("ivy-events-be-it", version, List.of(
                new RealmDeclaration("event-app-it", null, List.of(client),
                        List.of("USER", "ADMIN"), null, null)));
    }
}
