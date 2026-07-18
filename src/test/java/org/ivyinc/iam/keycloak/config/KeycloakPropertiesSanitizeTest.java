package org.ivyinc.iam.keycloak.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Directly exercises {@link KeycloakProperties#sanitize(String)}. Anchors
 * the exact env-value hygiene rules the prod 401 incident (trailing space
 * in {@code KEYCLOAK_ADMIN_CLIENT_SECRET}) taught us to enforce.
 */
class KeycloakPropertiesSanitizeTest {

    @Test
    @DisplayName("Trailing whitespace is stripped")
    void trimsTrailingWhitespace() {
        assertThat(KeycloakProperties.sanitize("admin-service   ")).isEqualTo("admin-service");
        assertThat(KeycloakProperties.sanitize("  admin-service")).isEqualTo("admin-service");
        assertThat(KeycloakProperties.sanitize("\tadmin-service\n")).isEqualTo("admin-service");
    }

    @Test
    @DisplayName("Trailing shell-redirect '>' is stripped (with any preceding whitespace)")
    void stripsTrailingRedirectArrow() {
        assertThat(KeycloakProperties.sanitize("https://x.mk/token                     >"))
                .isEqualTo("https://x.mk/token");
        assertThat(KeycloakProperties.sanitize("value >"))
                .isEqualTo("value");
        assertThat(KeycloakProperties.sanitize("value>"))
                .isEqualTo("value");
        assertThat(KeycloakProperties.sanitize("value >>>"))
                .isEqualTo("value");
    }

    @Test
    @DisplayName("Wrapping quotes are stripped")
    void stripsWrappingQuotes() {
        assertThat(KeycloakProperties.sanitize("\"admin-service\"")).isEqualTo("admin-service");
        assertThat(KeycloakProperties.sanitize("'admin-service'")).isEqualTo("admin-service");
        // But NOT embedded quotes:
        assertThat(KeycloakProperties.sanitize("admin\"middle\"service")).isEqualTo("admin\"middle\"service");
    }

    @Test
    @DisplayName("Clean values pass through unchanged")
    void cleanValuePassThrough() {
        assertThat(KeycloakProperties.sanitize("admin-service")).isEqualTo("admin-service");
        assertThat(KeycloakProperties.sanitize("https://auth.test.ivyevents.mk/realms/event-app/protocol/openid-connect/token"))
                .isEqualTo("https://auth.test.ivyevents.mk/realms/event-app/protocol/openid-connect/token");
    }

    @Test
    @DisplayName("Combined pollution: quotes + whitespace + redirect")
    void combinedPollutionAllStripped() {
        assertThat(KeycloakProperties.sanitize("  \"admin-service\"   >  "))
                .isEqualTo("admin-service");
    }

    @Test
    @DisplayName("normalize() writes back sanitized values via reflection")
    void normalizeAppliesSanitizeAcrossAllStringFields() {
        KeycloakProperties props = new KeycloakProperties();
        props.setAdminClientId("admin-service   ");
        props.setAdminClientSecret("\"secret\"");
        props.setBaseUrl("https://auth.local >");

        props.normalize();

        assertThat(props.getAdminClientId()).isEqualTo("admin-service");
        assertThat(props.getAdminClientSecret()).isEqualTo("secret");
        assertThat(props.getBaseUrl()).isEqualTo("https://auth.local");
    }
}
