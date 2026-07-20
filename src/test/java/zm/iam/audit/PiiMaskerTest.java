package zm.iam.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PiiMaskerTest {

    @ParameterizedTest(name = "{0} → {1}")
    @CsvSource({
            "alice@example.mk,        a****@example.mk",
            "z@x.mk,                  z@x.mk",
            "long-name@ivyevents.mk,  l********@ivyevents.mk",
            "no-at-sign,              ***",
            "'',                      ''"
    })
    void masksEmailLocalPart(String input, String expected) {
        assertThat(PiiMasker.maskEmail(input)).isEqualTo(expected);
    }

    @Test
    @DisplayName("Multivalued PII keys keep the key + a count, drop the values")
    void multivaluedPiiCollapsedToCount() {
        Map<String, Object> in = Map.of("eventIds", List.of("uuid-1", "uuid-2", "uuid-3"));
        assertThat(PiiMasker.sanitiseDetail(in)).containsEntry("eventIds", "<3 values>");
    }

    @Test
    @DisplayName("Forbidden keys → literal '[redacted]', never the value")
    void forbiddenKeysRedacted() {
        Map<String, Object> in = Map.of(
                "temporaryPassword", "hunter2",
                "clientSecret", "sh3-secret",
                "otp", "123456");
        Map<String, Object> out = PiiMasker.sanitiseDetail(in);
        assertThat(out.get("temporaryPassword")).isEqualTo("[redacted]");
        assertThat(out.get("clientSecret")).isEqualTo("[redacted]");
        assertThat(out.get("otp")).isEqualTo("[redacted]");
    }

    @Test
    @DisplayName("Non-PII keys pass through unchanged")
    void safeKeysPassThrough() {
        Map<String, Object> in = Map.of("changeCount", 5, "operation", "APPLY");
        assertThat(PiiMasker.sanitiseDetail(in))
                .containsEntry("changeCount", 5)
                .containsEntry("operation", "APPLY");
    }

    @Test
    @DisplayName("Null detail input → empty map (never NPE)")
    void nullDetailIsEmpty() {
        assertThat(PiiMasker.sanitiseDetail(null)).isEmpty();
    }
}
