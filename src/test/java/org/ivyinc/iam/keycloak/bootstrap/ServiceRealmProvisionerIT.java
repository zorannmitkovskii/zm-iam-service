package org.ivyinc.iam.keycloak.bootstrap;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.ivyinc.iam.keycloak.KeycloakAdminSession;
import org.ivyinc.iam.keycloak.config.KeycloakProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
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
 * Full integration test for {@link ServiceRealmProvisioner} against a
 * real Keycloak 26.2 container + a real Postgres (needed for Spring JPA
 * context to boot).
 *
 * <p>Verifies:
 * <ul>
 *   <li>Idempotent creation: {@code zm-services} realm + {@code iam-client}
 *       role present after {@code ApplicationReadyEvent}.</li>
 *   <li>Second explicit call is a no-op: realm's id and role's id
 *       unchanged after re-running provision().</li>
 * </ul>
 *
 * <p>Uses static-initialiser bootstrapping so the Keycloak container is
 * up + the {@code admin-service} client is seeded BEFORE Spring context
 * initialises — otherwise the provisioner would try to authenticate
 * against an empty master realm during ApplicationReadyEvent.
 */
@Testcontainers
@SpringBootTest
class ServiceRealmProvisionerIT {

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
        // Explicit start so we can seed the admin-service client BEFORE the
        // Spring context initialises. Do NOT rely on @Container lifecycle
        // ordering vs SpringExtension here — mixing extensions caused
        // "master realm empty" flakes historically.
        KEYCLOAK.start();
        POSTGRES.start();
        seedAdminServiceClient();
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);

        registry.add("iam.keycloak.base-url", KEYCLOAK::getAuthServerUrl);
        registry.add("iam.keycloak.admin-client-id", () -> ADMIN_SERVICE_CLIENT_ID);
        registry.add("iam.keycloak.admin-client-secret", () -> ADMIN_SERVICE_SECRET);
        registry.add("iam.keycloak.admin-realm", () -> "master");
        registry.add("iam.keycloak.self-bootstrap-enabled", () -> "true");
        registry.add("iam.keycloak.zm-services-realm", () -> "zm-services");
        registry.add("iam.keycloak.iam-client-role", () -> "iam-client");
    }

    /** Creates a confidential {@code admin-service} client in master with
     *  {@code service_accounts_enabled=true}, then grants its service-account
     *  user the {@code admin} realm role — the standard way to expose full
     *  admin power to a machine principal. */
    private static void seedAdminServiceClient() {
        try (Keycloak master = KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK.getAuthServerUrl())
                .realm("master")
                .username(KEYCLOAK.getAdminUsername())
                .password(KEYCLOAK.getAdminPassword())
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
            UserRepresentation serviceAccountUser =
                    masterRealm.clients().get(clientUuid).getServiceAccountUser();

            RoleRepresentation adminRole = masterRealm.roles().get("admin").toRepresentation();
            masterRealm.users().get(serviceAccountUser.getId())
                    .roles().realmLevel().add(List.of(adminRole));
        }
    }

    @Autowired KeycloakAdminSession session;
    @Autowired KeycloakProperties props;
    @Autowired ServiceRealmProvisioner provisioner;

    @Test
    @DisplayName("Provisioner creates zm-services realm + iam-client role during ApplicationReadyEvent")
    void provisionCreatesRealmAndRole() {
        try (Keycloak admin = session.client()) {
            RealmRepresentation realm = admin.realm(props.getZmServicesRealm()).toRepresentation();
            assertThat(realm.getRealm()).isEqualTo(props.getZmServicesRealm());
            assertThat(realm.isEnabled()).isTrue();
            assertThat(realm.isRegistrationAllowed()).isFalse();
            assertThat(realm.isLoginWithEmailAllowed()).isFalse();

            RoleRepresentation role = admin.realm(props.getZmServicesRealm())
                    .roles().get(props.getIamClientRole()).toRepresentation();
            assertThat(role.getName()).isEqualTo(props.getIamClientRole());
            // getClientRole() returns Boolean (may be null for realm roles in
            // some serialisation paths) — treat null as "not a client role".
            assertThat(role.getClientRole() == null || !role.getClientRole()).isTrue();
        }
    }

    @Test
    @DisplayName("Second provision() call is a no-op: realm id + role id unchanged")
    void secondRunIsNoOp() {
        String realmName = props.getZmServicesRealm();
        String roleName = props.getIamClientRole();

        String realmIdBefore;
        String roleIdBefore;
        try (Keycloak admin = session.client()) {
            realmIdBefore = admin.realm(realmName).toRepresentation().getId();
            roleIdBefore = admin.realm(realmName).roles().get(roleName).toRepresentation().getId();
        }

        // Re-run explicitly — should be idempotent, no writes.
        provisioner.provision();

        try (Keycloak admin = session.client()) {
            String realmIdAfter = admin.realm(realmName).toRepresentation().getId();
            String roleIdAfter = admin.realm(realmName).roles().get(roleName).toRepresentation().getId();
            assertThat(realmIdAfter).isEqualTo(realmIdBefore);
            assertThat(roleIdAfter).isEqualTo(roleIdBefore);
        }
    }
}
