package zm.iam.provisioning.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Rule-by-rule validation checks on {@link ServiceProvisioningManifest}.
 * One valid + one invalid case per constraint — enough to anchor the
 * shape without going Cartesian.
 */
class ManifestValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    // ── serviceId ────────────────────────────────────────────────

    @Test
    @DisplayName("Uppercase serviceId → fails pattern")
    void serviceIdMustBeLowercase() {
        var m = manifest("EventsBE", 1);
        assertThat(paths(validator.validate(m))).contains("serviceId");
    }

    @Test
    @DisplayName("serviceId over 64 chars → fails Size")
    void serviceIdMaxLength() {
        String tooLong = "a".repeat(65);
        var m = manifest(tooLong, 1);
        assertThat(paths(validator.validate(m))).contains("serviceId");
    }

    // ── manifestVersion ──────────────────────────────────────────

    @Test
    @DisplayName("Zero manifestVersion → fails Positive")
    void versionZeroFails() {
        var m = manifest("svc", 0);
        assertThat(paths(validator.validate(m))).contains("manifestVersion");
    }

    @Test
    @DisplayName("Negative manifestVersion → fails")
    void versionNegativeFails() {
        var m = manifest("svc", -3);
        assertThat(paths(validator.validate(m))).contains("manifestVersion");
    }

    // ── realms non-empty ─────────────────────────────────────────

    @Test
    @DisplayName("Empty realms list → fails NotEmpty")
    void realmsMustBeNonEmpty() {
        var m = new ServiceProvisioningManifest("svc", 1, List.of());
        assertThat(paths(validator.validate(m))).contains("realms");
    }

    // ── unique realm names ───────────────────────────────────────

    @Test
    @DisplayName("Duplicate realm names → fails class-level @AssertTrue")
    void duplicateRealmNamesRejected() {
        var m = new ServiceProvisioningManifest("svc", 1, List.of(
                realm("r"),
                realm("r")
        ));
        assertThat(paths(validator.validate(m))).contains("realmNamesUnique");
    }

    // ── zm-services scope ────────────────────────────────────────

    @Test
    @DisplayName("Client with foreign clientId in zm-services → rejected")
    void zmServicesForeignClientRejected() {
        ClientDeclaration foreign = new ClientDeclaration(
                "evil-client", ClientType.CONFIDENTIAL,
                null, null, null, null, null, null);
        RealmDeclaration zm = new RealmDeclaration(
                ServiceProvisioningManifest.ZM_SERVICES_REALM,
                null, List.of(foreign), null, null, null);
        var m = new ServiceProvisioningManifest("ivy-events-be", 1, List.of(zm));
        assertThat(paths(validator.validate(m))).contains("zmServicesScopeRespected");
    }

    @Test
    @DisplayName("Correct '{serviceId}-svc' client in zm-services → accepted")
    void zmServicesCorrectClientAccepted() {
        ClientDeclaration ok = new ClientDeclaration(
                "ivy-events-be-svc", ClientType.CONFIDENTIAL,
                null, null, null, true, List.of("iam-client"), null);
        RealmDeclaration zm = new RealmDeclaration(
                ServiceProvisioningManifest.ZM_SERVICES_REALM,
                null, List.of(ok), null, null, null);
        var m = new ServiceProvisioningManifest("ivy-events-be", 1, List.of(zm));
        assertThat(validator.validate(m)).isEmpty();
    }

    // ── clientId pattern ─────────────────────────────────────────

    @Test
    @DisplayName("clientId with space → fails pattern")
    void clientIdRejectsSpace() {
        ClientDeclaration bad = new ClientDeclaration(
                "bad client", ClientType.PUBLIC,
                null, null, null, null, null, null);
        var m = new ServiceProvisioningManifest("svc", 1, List.of(
                new RealmDeclaration("r", null, List.of(bad), null, null, null)
        ));
        assertThat(paths(validator.validate(m)))
                .anyMatch(p -> p.contains("clientId"));
    }

    // ── IdP env-ref format ───────────────────────────────────────

    @Test
    @DisplayName("Lowercase envRef → fails UPPER_SNAKE_CASE pattern")
    void envRefMustBeUpperSnake() {
        IdentityProviderDeclaration bad = new IdentityProviderDeclaration(
                "google", "GOOGLE", "my_client_id", "MY_SECRET");
        RealmDeclaration r = new RealmDeclaration(
                "r", null, null, null, List.of(bad), null);
        var m = new ServiceProvisioningManifest("svc", 1, List.of(r));
        assertThat(paths(validator.validate(m)))
                .anyMatch(p -> p.contains("clientIdEnvRef"));
    }

    // ── helpers ──────────────────────────────────────────────────

    private static ServiceProvisioningManifest manifest(String serviceId, int version) {
        return new ServiceProvisioningManifest(serviceId, version, List.of(realm("app")));
    }

    private static RealmDeclaration realm(String name) {
        return new RealmDeclaration(name, null, null, null, null, null);
    }

    private static Set<String> paths(Set<ConstraintViolation<ServiceProvisioningManifest>> violations) {
        return violations.stream()
                .map(v -> v.getPropertyPath().toString())
                .collect(Collectors.toSet());
    }
}
