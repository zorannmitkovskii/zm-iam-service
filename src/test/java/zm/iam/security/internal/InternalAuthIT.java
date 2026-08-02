package zm.iam.security.internal;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
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
import zm.iam.provisioning.ownership.OwnershipService;
import zm.iam.provisioning.ownership.ResourceType;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end proof that IAM-09's filter chain does what the ticket
 * demands. Uses a REAL Keycloak container so the JWT signatures + JWKS
 * discovery + issuer validation all run against production-shaped
 * tokens, not stubs.
 *
 * <p>Flow of the happy-path test:
 * <ol>
 *   <li>Boot Keycloak 26 + Postgres via Testcontainers.</li>
 *   <li>Seed {@code admin-service} in the master realm (so IAM can
 *       authenticate as admin — same helper the other IT uses).</li>
 *   <li>Let {@code SelfBootstrap} create the {@code zm-services} realm
 *       and {@code iam-client} role on ApplicationReady.</li>
 *   <li>Apply a manifest that (a) creates {@code event-app-it}
 *       realm and (b) declares a CONFIDENTIAL
 *       {@code ivy-events-be-svc} client in {@code zm-services} with
 *       service accounts enabled.</li>
 *   <li>Post-apply, bind the {@code iam-client} realm role to the
 *       svc client's service-account user (the reconciler doesn't do
 *       this yet — deferred to a later IAM ticket).</li>
 *   <li>Fetch a client_credentials token for {@code ivy-events-be-svc}
 *       from {@code zm-services}, POST it as a Bearer, expect 200.</li>
 * </ol>
 *
 * <p>Negative-path tests reuse the same container/realm state but call
 * a fresh HTTP client for each case.
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class InternalAuthIT {

    private static final String ADMIN_SERVICE_CLIENT_ID = "admin-service";
    private static final String ADMIN_SERVICE_SECRET    = "it-secret";

    private static final String IVY_SVC_CLIENT_ID = "ivy-events-be-svc";
    private static final String IVY_SVC_SECRET    = "ivy-svc-it-secret";

    private static final String EVENT_APP_REALM = "event-app-it";
    private static final String PRESMETKO_REALM = "presmetko-it";
    private static final String APP_USER = "alice";
    private static final String APP_USER_PASSWORD = "wonderland";

    // ── containers ─────────────────────────────────────────────────
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
        // Shared helper — same one ProvisioningIT uses to seed the
        // admin service account in the master realm.
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
        // The issuer inside the token is EXACTLY the URL Keycloak sees
        // itself as; we point the resource-server JwtDecoder at the same
        // URL so JWK discovery + iss validation align.
        r.add("iam.security.internal.issuer-uri",
                () -> trimSlash(KEYCLOAK.getAuthServerUrl()) + "/realms/zm-services");
    }

    private static String trimSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    @LocalServerPort int serverPort;

    @Autowired ProvisioningService provisioningService;
    @Autowired OwnedRealmsCache ownedRealmsCache;
    @Autowired OwnershipService ownershipService;
    @Value("${iam.security.internal.issuer-uri}") String issuerUri;

    private static boolean seeded = false;

    @BeforeAll
    static void resetSeededFlag() {
        // Static across the whole class — reset each JVM run so parallel
        // Failsafe forks don't interfere.
        seeded = false;
    }

    /** One-time setup for the whole class, but called lazily from the
     *  first test so we can use injected beans. JUnit's @BeforeEach
     *  would re-run this on every test. */
    private void ensureSeeded() {
        if (seeded) return;

        // 1. Apply a manifest that creates event-app-it realm + the
        //    ivy-events-be-svc CONFIDENTIAL client in zm-services.
        ClientDeclaration svcClient = new ClientDeclaration(
                IVY_SVC_CLIENT_ID, ClientType.CONFIDENTIAL, false,
                null, null,
                true, null, null, List.of("iam-client"), null);
        ClientDeclaration feClient = new ClientDeclaration(
                "eventFE-it", ClientType.PUBLIC, true,
                List.of("https://example.mk/*"), List.of("+"),
                null, null, null, null, null);
        ServiceProvisioningManifest manifest = new ServiceProvisioningManifest(
                "ivy-events-be", 1, List.of(
                new RealmDeclaration(EVENT_APP_REALM, null, List.of(feClient),
                        List.of("USER"), null, null),
                new RealmDeclaration("zm-services", null, List.of(svcClient),
                        null, null, null)
        ));
        ApplyResult result = provisioningService.apply(manifest);
        assertThat(result.status()).isEqualTo(ApplyResult.Status.APPLIED);

        // Cross-realm case needs a SECOND owner in the DB — we plant it
        // directly rather than applying a whole extra manifest.
        ownershipService.registerBootstrap(PRESMETKO_REALM, PRESMETKO_REALM, ResourceType.REALM);
        // Invalidate to make sure the fresh row is visible.
        ownedRealmsCache.invalidateAll();

        // 2. The reconciler creates the client but doesn't set our own
        //    known secret and doesn't bind the iam-client role to its
        //    service-account user. Do both directly via admin API.
        try (Keycloak admin = adminClient()) {
            RealmResource zm = admin.realm("zm-services");
            ClientRepresentation svc = zm.clients().findByClientId(IVY_SVC_CLIENT_ID).get(0);
            svc.setSecret(IVY_SVC_SECRET);
            zm.clients().get(svc.getId()).update(svc);
            // Bind iam-client role to the service account user
            UserRepresentation saUser = zm.clients().get(svc.getId()).getServiceAccountUser();
            RoleRepresentation iamClientRole = zm.roles().get("iam-client").toRepresentation();
            zm.users().get(saUser.getId()).roles().realmLevel().add(List.of(iamClientRole));

            // 3. Create an app-realm user + password so we can prove the
            //    "user token from event-app is rejected" AC.
            ensureAppUser(admin);
        }

        seeded = true;
    }

    private void ensureAppUser(Keycloak admin) {
        RealmResource realm = admin.realm(EVENT_APP_REALM);
        // A public client with direct-access grants enabled is required
        // for the password grant flow. Manifest's PUBLIC client had
        // directAccessGrantsEnabled=false — patch it here.
        ClientRepresentation fe = realm.clients().findByClientId("eventFE-it").get(0);
        fe.setDirectAccessGrantsEnabled(true);
        realm.clients().get(fe.getId()).update(fe);

        // Keycloak 24+ User Profile rejects users without firstName /
        // lastName by default. Set both, and turn on unmanaged attributes
        // for the realm so we're never surprised by profile validation
        // during the password-grant flow.
        try {
            var upResource = realm.users().userProfile();
            var upCfg = upResource.getConfiguration();
            upCfg.setUnmanagedAttributePolicy(
                    org.keycloak.representations.userprofile.config.UPConfig.UnmanagedAttributePolicy.ENABLED);
            upResource.update(upCfg);
        } catch (Exception ignored) {
            // Older Keycloak versions may not expose UPConfig — the
            // defaults are permissive enough for this test.
        }

        UserRepresentation user = new UserRepresentation();
        user.setUsername(APP_USER);
        user.setEmail(APP_USER + "@example.mk");
        user.setFirstName("Alice");
        user.setLastName("Wonderland");
        user.setEnabled(true);
        user.setEmailVerified(true);
        Response created = realm.users().create(user);
        String uid = extractIdFromLocation(created);
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(APP_USER_PASSWORD);
        cred.setTemporary(false);
        realm.users().get(uid).resetPassword(cred);
    }

    private static String extractIdFromLocation(Response r) {
        String loc = r.getHeaderString("Location");
        return loc.substring(loc.lastIndexOf('/') + 1);
    }

    private Keycloak adminClient() {
        return KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK.getAuthServerUrl())
                .realm("master")
                .clientId(ADMIN_SERVICE_CLIENT_ID)
                .clientSecret(ADMIN_SERVICE_SECRET)
                .grantType("client_credentials")
                .build();
    }

    // ── tests ──────────────────────────────────────────────────────

    @Test
    @DisplayName("AC 4 — valid svc token + owned realm → 200")
    void serviceTokenForOwnedRealmSucceeds() throws Exception {
        ensureSeeded();

        String token = fetchClientCredentialsToken();
        int status = getInternal(token, EVENT_APP_REALM);

        assertThat(status).isEqualTo(200);
    }

    @Test
    @DisplayName("AC 1 — no bearer token → 401")
    void noTokenIs401() throws Exception {
        ensureSeeded();

        int status = getInternalNoAuth(EVENT_APP_REALM);

        assertThat(status).isEqualTo(401);
    }

    @Test
    @DisplayName("AC 3 — user token from event-app realm → 401 (wrong issuer)")
    void userTokenFromWrongRealmIs401() throws Exception {
        ensureSeeded();

        String userToken = fetchUserPasswordGrantToken();
        int status = getInternal(userToken, EVENT_APP_REALM);

        // Wrong issuer → JWT validation fails before authz runs. Spring
        // Security returns 401 with an OAuth2 Bearer challenge.
        assertThat(status).isEqualTo(401);
    }

    @Test
    @DisplayName("AC 5 — svc token but cross-realm target → 403 with owner in body")
    void crossRealmIs403() throws Exception {
        ensureSeeded();

        String token = fetchClientCredentialsToken();
        HttpResponse<String> resp = getInternalFull(token, PRESMETKO_REALM);

        assertThat(resp.statusCode()).isEqualTo(403);
        assertThat(resp.body()).contains(PRESMETKO_REALM);
    }

    @Test
    @DisplayName("AC 6 — post-apply cache invalidation: newly-owned realm becomes reachable without restart")
    void cacheInvalidationOnApply() throws Exception {
        ensureSeeded();

        // Warm the cache with the CURRENT owned set.
        String token = fetchClientCredentialsToken();
        assertThat(getInternal(token, EVENT_APP_REALM)).isEqualTo(200);

        // Add a brand-new realm to ivy-events-be's ownership via a fresh
        // manifest version. This must fire the invalidation hook in
        // ProvisioningService.apply() so the next authz check sees it.
        String newRealm = "event-app-secondary-it";
        ClientDeclaration svcClient = new ClientDeclaration(
                IVY_SVC_CLIENT_ID, ClientType.CONFIDENTIAL, false,
                null, null, true, null, null, List.of("iam-client"), null);
        ClientDeclaration feClient = new ClientDeclaration(
                "feSecondary", ClientType.PUBLIC, true,
                List.of("https://example.mk/*"), List.of("+"),
                null, null, null, null, null);
        ServiceProvisioningManifest v2 = new ServiceProvisioningManifest(
                "ivy-events-be", 2, List.of(
                new RealmDeclaration(newRealm, null, List.of(feClient),
                        List.of("USER"), null, null),
                new RealmDeclaration("zm-services", null, List.of(svcClient),
                        null, null, null)
        ));
        provisioningService.apply(v2);

        // Without cache invalidation this would still 403 (cached set
        // has no 'event-app-secondary-it'). With it, we get 200.
        assertThat(getInternal(token, newRealm)).isEqualTo(200);
    }

    @Test
    @DisplayName("AC 7 — /actuator/health still open without auth")
    void actuatorHealthIsOpen() throws Exception {
        HttpResponse<String> resp = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:" + serverPort + "/actuator/health"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(200);
    }

    // ── HTTP helpers ───────────────────────────────────────────────

    private String fetchClientCredentialsToken() {
        try (Keycloak client = KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK.getAuthServerUrl())
                .realm("zm-services")
                .clientId(IVY_SVC_CLIENT_ID)
                .clientSecret(IVY_SVC_SECRET)
                .grantType("client_credentials")
                .build()) {
            return client.tokenManager().getAccessTokenString();
        }
    }

    private String fetchUserPasswordGrantToken() {
        try (Keycloak client = KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK.getAuthServerUrl())
                .realm(EVENT_APP_REALM)
                .clientId("eventFE-it")
                .username(APP_USER)
                .password(APP_USER_PASSWORD)
                .grantType("password")
                .build()) {
            return client.tokenManager().getAccessTokenString();
        }
    }

    private int getInternal(String bearer, String realm) throws Exception {
        return getInternalFull(bearer, realm).statusCode();
    }

    private HttpResponse<String> getInternalFull(String bearer, String realm) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort
                        + "/internal/users/search?realm=" + realm))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .GET().build();
        return HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
    }

    private int getInternalNoAuth(String realm) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + serverPort
                        + "/internal/users/search?realm=" + realm))
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .GET().build();
        return HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    /** Suppress unused warnings for the realm creation helper class import. */
    @SuppressWarnings("unused")
    private static final Class<?> UNUSED_REALM_REP = RealmRepresentation.class;
}
