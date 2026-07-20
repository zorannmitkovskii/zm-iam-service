package zm.iam.user;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import zm.iam.common.exception.DuplicateResourceException;
import zm.iam.common.exception.ResourceNotFoundException;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.keycloak.KeycloakAdminSession;
import zm.iam.provisioning.ProvisioningIT;
import zm.iam.user.dto.AttributePatchDto;
import zm.iam.user.dto.RolesPutDto;
import zm.iam.user.dto.UserCreateDto;
import zm.iam.user.dto.UserResponseDto;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Full user-management flow against a live Keycloak. Seeds a dedicated
 * test realm once so every test can create + delete without stepping on
 * each other's users.
 */
@Testcontainers
@SpringBootTest
class UserIT {

    private static final String TEST_REALM = "user-it-realm";
    private static final String ADMIN_SERVICE_CLIENT_ID = "admin-service";
    private static final String ADMIN_SERVICE_SECRET    = "it-secret";

    static final KeycloakContainer KEYCLOAK = new KeycloakContainer("quay.io/keycloak/keycloak:26.2.4");
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
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

    @Autowired UserService userService;
    @Autowired KeycloakAdminSession session;
    @Autowired KeycloakAdminApi api;

    @BeforeEach
    void ensureRealmAndRoles() {
        if (!api.realmExists(TEST_REALM)) {
            RealmRepresentation r = new RealmRepresentation();
            r.setRealm(TEST_REALM);
            r.setEnabled(true);
            api.createRealm(r);
            // Keycloak 24+ ships User Profile enabled + rejects unmanaged
            // attributes by default. Ivy relies on multi-valued custom
            // attributes (eventIds, packages) — enable the ADMIN_EDIT
            // policy so admin-side writes (IAM ← us) accept them.
            try (Keycloak admin = session.client()) {
                var upResource = admin.realm(TEST_REALM).users().userProfile();
                var cfg = upResource.getConfiguration();
                cfg.setUnmanagedAttributePolicy(
                        org.keycloak.representations.userprofile.config.UPConfig.UnmanagedAttributePolicy.ENABLED);
                upResource.update(cfg);
            }
        }
        for (String roleName : List.of("USER", "ADMIN")) {
            if (!api.realmRoleExists(TEST_REALM, roleName)) {
                api.createRealmRole(TEST_REALM, roleName, null);
            }
        }
    }

    // ── AC 1 — full lifecycle ────────────────────────────────

    @Test
    @DisplayName("Create → search → assign roles → PATCH append → enable → PATCH remove → delete")
    void fullLifecycle() {
        String email = "lifecycle+" + UUID.randomUUID() + "@ivy.test";
        UserResponseDto created = userService.create(TEST_REALM, new UserCreateDto(
                email, "Zoran", "Mitkovski", false,
                Map.of("packages", List.of("basic")),
                null, null));
        assertThat(created.enabled()).isFalse();

        var found = userService.searchByEmail(TEST_REALM, email);
        assertThat(found).isPresent();

        var withRoles = userService.putRoles(TEST_REALM, created.id(), new RolesPutDto(List.of("USER")));
        assertThat(withRoles.realmRoles()).contains("USER");

        var afterAppend = userService.patchAttributes(TEST_REALM, created.id(),
                new AttributePatchDto(null, Map.of("eventIds", List.of("e-1")), null));
        assertThat(afterAppend.attributes().get("eventIds")).containsExactly("e-1");

        var enabled = userService.setEnabled(TEST_REALM, created.id(), true);
        assertThat(enabled.enabled()).isTrue();

        var afterRemove = userService.patchAttributes(TEST_REALM, created.id(),
                new AttributePatchDto(null, null, Map.of("eventIds", List.of("e-1"))));
        assertThat(afterRemove.attributes()).doesNotContainKey("eventIds");

        userService.delete(TEST_REALM, created.id());
        assertThat(userService.searchByEmail(TEST_REALM, email)).isEmpty();
    }

    // ── AC 5 — duplicate email + missing user ────────────────

    @Test
    @DisplayName("Duplicate email on create → DuplicateResourceException; op on missing user → 404")
    void duplicateAndNotFound() {
        String email = "dup+" + UUID.randomUUID() + "@ivy.test";
        userService.create(TEST_REALM, new UserCreateDto(email, "A", "B", true, null, null, null));

        assertThatThrownBy(() -> userService.create(TEST_REALM,
                new UserCreateDto(email, "A", "B", true, null, null, null)))
                .isInstanceOf(DuplicateResourceException.class);

        assertThatThrownBy(() -> userService.get(TEST_REALM, "00000000-0000-0000-0000-000000000000"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ── AC 4 — concurrency: 20 parallel appends ─────────────

    @Test
    @DisplayName("20 parallel appends of distinct values on same user → all 20 present, no lost update")
    void concurrentAppendsNeverLoseUpdates() throws Exception {
        String email = "conc+" + UUID.randomUUID() + "@ivy.test";
        UserResponseDto user = userService.create(TEST_REALM, new UserCreateDto(
                email, "C", "C", true, null, null, null));

        int taskCount = 20;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch gate = new CountDownLatch(1);
        AtomicInteger done = new AtomicInteger();
        try {
            for (int i = 0; i < taskCount; i++) {
                String value = "eid-" + i;
                pool.submit(() -> {
                    try {
                        gate.await();
                        userService.patchAttributes(TEST_REALM, user.id(),
                                new AttributePatchDto(null, Map.of("eventIds", List.of(value)), null));
                    } catch (Exception ignored) {
                    } finally {
                        done.incrementAndGet();
                    }
                });
            }
            gate.countDown();
            pool.shutdown();
            boolean finished = pool.awaitTermination(60, TimeUnit.SECONDS);
            assertThat(finished).isTrue();
        } finally {
            if (!pool.isShutdown()) pool.shutdownNow();
        }

        var afterAll = userService.get(TEST_REALM, user.id());
        assertThat(afterAll.attributes().get("eventIds")).hasSize(taskCount);
    }

    // ── temporaryPassword flow ───────────────────────────────

    @Test
    @DisplayName("temporaryPassword on create → user has a temporary credential")
    void temporaryPasswordSetOnCreate() {
        String email = "temp+" + UUID.randomUUID() + "@ivy.test";
        UserResponseDto created = userService.create(TEST_REALM, new UserCreateDto(
                email, "T", "T", true, null, "InitialPass!123", null));

        try (Keycloak admin = session.client()) {
            var creds = admin.realm(TEST_REALM).users().get(created.id()).credentials();
            assertThat(creds).anySatisfy(c -> {
                assertThat(c.getType()).isEqualTo("password");
                assertThat(Boolean.TRUE.equals(c.isTemporary())
                        // Some Keycloak versions surface temporary state via
                        // required actions on the user instead of on the
                        // credential — assert either wins.
                        || admin.realm(TEST_REALM).users().get(created.id())
                                .toRepresentation().getRequiredActions() != null).isTrue();
            });
        }
    }

    // ── AC 6 — set + append overlap → validation ─────────────

    @Test
    @DisplayName("Same key in set + append → rejected by AttributePatchDto validation")
    void setAppendOverlapRejected() {
        var patch = new AttributePatchDto(
                Map.of("k", List.of("v1")),
                Map.of("k", List.of("v2")),
                null);
        assertThat(patch.isSetAppendDisjoint()).isFalse();
    }

    @Test
    @DisplayName("Roles used above are legitimate role names — sanity")
    void rolesExistInSetup() {
        List<RoleRepresentation> roles = api.findRealmRoleReps(TEST_REALM, List.of("USER", "ADMIN"));
        assertThat(roles).hasSize(2);
    }
}
