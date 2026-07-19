package org.ivyinc.iam.provisioning;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.ivyinc.iam.provisioning.dto.ServiceProvisioningManifest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Fixture-driven contract tests. Any valid YAML in {@code valid/} must
 * parse + validate successfully; every invalid file names its specific
 * violation and points at the (property-path, keyword) we expect to see.
 *
 * <p>These fixtures double as the reference set the client library
 * (IAM-07) will reuse — moving or renaming them means updating that
 * library too.
 */
class ManifestFixturesTest {

    private final ObjectMapper yaml = strict(new ObjectMapper(new YAMLFactory()));
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    // ── valid/ ──────────────────────────────────────────────────

    @Test
    @DisplayName("valid/ivy.yml — full Ivy manifest parses + validates")
    void ivyManifestIsValid() throws Exception {
        var m = load("valid/ivy.yml");
        Set<ConstraintViolation<ServiceProvisioningManifest>> violations = validator.validate(m);
        assertThat(violations).isEmpty();
        assertThat(m.serviceId()).isEqualTo("ivy-events-be");
        assertThat(m.realms()).hasSize(2);
    }

    @Test
    @DisplayName("valid/minimal.yml — smallest manifest validates")
    void minimalManifestIsValid() throws Exception {
        var m = load("valid/minimal.yml");
        assertThat(validator.validate(m)).isEmpty();
    }

    // ── invalid/ ────────────────────────────────────────────────

    @ParameterizedTest(name = "{0} → contains constraint on '{1}'")
    @CsvSource({
            "invalid/serviceId-uppercase.yml,        serviceId",
            "invalid/version-zero.yml,               manifestVersion",
            "invalid/duplicate-realms.yml,           realmNamesUnique",
            "invalid/zm-services-foreign-client.yml, zmServicesScopeRespected"
    })
    void invalidFixturesFailWithExpectedPath(String fixture, String expectedPathFragment) throws Exception {
        var m = load(fixture);
        Set<ConstraintViolation<ServiceProvisioningManifest>> violations = validator.validate(m);
        assertThat(violations).isNotEmpty();
        assertThat(violations)
                .anyMatch(v -> v.getPropertyPath().toString().contains(expectedPathFragment));
    }

    @Test
    @DisplayName("invalid/idp-plaintext-secret.yml — unknown property fails at PARSE time")
    void plaintextSecretRejectedAtParse() {
        assertThatThrownBy(() -> load("invalid/idp-plaintext-secret.yml"))
                .isInstanceOf(UnrecognizedPropertyException.class)
                .hasMessageContaining("clientSecret");
    }

    // ── helpers ─────────────────────────────────────────────────

    private ServiceProvisioningManifest load(String classpathPath) throws Exception {
        try (var in = getClass().getClassLoader().getResourceAsStream("manifests/" + classpathPath)) {
            if (in == null) throw new IllegalStateException("Fixture not found: " + classpathPath);
            return yaml.readValue(in, ServiceProvisioningManifest.class);
        }
    }

    private static ObjectMapper strict(ObjectMapper m) {
        m.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        m.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);
        return m;
    }
}
