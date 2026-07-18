package org.ivyinc.iam.keycloak.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

@Slf4j
@Getter
@Setter
@ConfigurationProperties(prefix = "iam.keycloak")
public class KeycloakProperties {

    private String baseUrl;
    private String adminClientId;
    private String adminClientSecret;
    /** Realm the admin client authenticates against. Default is Keycloak's
     *  built-in {@code master} realm — the only place a global admin service
     *  account can live. */
    private String adminRealm = "master";

    /** Realm SelfBootstrap creates (idempotently) on ApplicationReadyEvent.
     *  Houses service-account clients used by zm-* microservices to
     *  authenticate against IAM's internal endpoints. */
    private String zmServicesRealm = "zm-services";

    /** Realm role created inside {@link #zmServicesRealm} — every service
     *  account client gets this role so IAM can authorise them uniformly. */
    private String iamClientRole = "iam-client";

    /** Kill switch: {@code false} skips SelfBootstrap entirely. Use in
     *  environments where the realm was seeded out-of-band (Terraform, an
     *  imported realm.json, etc.) and you want zero Keycloak calls at
     *  startup. */
    private boolean selfBootstrapEnabled = true;

    // ── Token cache tunables (KeycloakAdminClientProvider) ──────────────

    /** Refresh the admin token once the remaining lifetime drops below this
     *  many seconds — 60s gives Gateway calls a safe execution window. */
    private int tokenRefreshLeadSeconds = 60;

    /** Max retry attempts when the Keycloak token endpoint fails with a
     *  transient error (connection refuse or 5xx). Exponential backoff:
     *  1s → 2s → 4s → 8s → 16s (base 2). */
    private int tokenFetchMaxAttempts = 5;

    /**
     * Normalises every String property once at container startup.
     *
     * <p>Env vars sourced from {@code .env} files, docker-compose, or
     * copy-paste routinely arrive with trailing whitespace, stray {@code >}
     * redirect characters, or wrapping quotes. Keycloak treats
     * {@code "admin-service   "} as distinct from {@code "admin-service"}
     * and Resteasy happily URL-encodes trailing spaces into
     * {@code %20%20...} — both cause confusing 401 errors on requests that
     * <em>look</em> correct in the log.
     *
     * <p>Reflection is deliberate: adding a new String field automatically
     * gets sanitised without touching this method.
     */
    @PostConstruct
    void normalize() {
        int trimmed = 0;
        int total = 0;
        for (Field f : KeycloakProperties.class.getDeclaredFields()) {
            if (!String.class.equals(f.getType())) continue;
            if (Modifier.isStatic(f.getModifiers())) continue;
            total++;
            try {
                f.setAccessible(true);
                String value = (String) f.get(this);
                if (value == null) continue;
                String cleaned = sanitize(value);
                if (!cleaned.equals(value)) {
                    f.set(this, cleaned);
                    trimmed++;
                    log.warn("[KeycloakProperties] Sanitized '{}' — length {} → {} (stripped whitespace/quotes/stray chars)",
                            f.getName(), value.length(), cleaned.length());
                }
            } catch (IllegalAccessException ignored) {
                // reflection on our own fields — cannot fail in practice
            }
        }
        if (trimmed == 0) {
            log.info("[KeycloakProperties] All {} string properties clean, no sanitization needed", total);
        }
    }

    /** Strip surrounding whitespace, wrapping quotes, and trailing
     *  shell-redirect characters that occasionally leak in from misauthored
     *  env files. Package-private for direct unit testing. */
    static String sanitize(String raw) {
        String s = raw.trim();
        while (s.endsWith(">")) s = s.substring(0, s.length() - 1).trim();
        if (s.length() >= 2) {
            char first = s.charAt(0);
            char last = s.charAt(s.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                s = s.substring(1, s.length() - 1).trim();
            }
        }
        return s;
    }
}
