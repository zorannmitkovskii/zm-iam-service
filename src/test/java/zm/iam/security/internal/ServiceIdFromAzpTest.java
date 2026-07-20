package zm.iam.security.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers every branch of {@link ServiceIdFromAzp#map(String)} — the
 * convention translator IAM-09 leans on to turn a Keycloak client id
 * into an ownership serviceId.
 */
class ServiceIdFromAzpTest {

    @ParameterizedTest(name = "azp='{0}' → serviceId='{1}'")
    @DisplayName("Valid -svc-suffixed client ids map to their serviceId prefix")
    @CsvSource({
            "ivy-events-be-svc,   ivy-events-be",
            "presmetko-be-svc,    presmetko-be",
            "a-svc,               a",
            "  ivy-events-be-svc  , ivy-events-be"      // whitespace trimmed
    })
    void validAzpMapsToServiceId(String azp, String expected) {
        assertThat(ServiceIdFromAzp.map(azp)).contains(expected);
    }

    @ParameterizedTest
    @DisplayName("Null/blank azp → empty (401 upstream)")
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void nullBlankIsEmpty(String azp) {
        assertThat(ServiceIdFromAzp.map(azp)).isEmpty();
    }

    @ParameterizedTest
    @DisplayName("Clients without -svc suffix are rejected — no serviceId derivable")
    @ValueSource(strings = {
            "ivy-events-be",             // missing suffix entirely
            "eventFE",                   // FE client id in an app realm
            "admin-cli",                 // Keycloak built-in
            "some-svc-other",            // suffix in the middle, not at the end
            "-svc"                       // suffix only, empty prefix
    })
    void nonSvcClientIsRejected(String azp) {
        assertThat(ServiceIdFromAzp.map(azp)).isEmpty();
    }

    @org.junit.jupiter.api.Test
    @DisplayName("Return type is Optional (never null)")
    void neverReturnsNull() {
        Optional<String> result = ServiceIdFromAzp.map("anything-svc");
        assertThat(result).isNotNull();
    }
}
