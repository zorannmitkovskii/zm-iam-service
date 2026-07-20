package zm.iam.security.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Keycloak puts realm roles in {@code realm_access.roles}. Verify our
 * converter surfaces them as {@code ROLE_*} authorities so
 * {@code hasRole("iam-client")} in SecurityConfig actually matches.
 */
class KeycloakRealmRolesJwtConverterTest {

    private final KeycloakRealmRolesJwtConverter converter = new KeycloakRealmRolesJwtConverter();

    @Test
    @DisplayName("realm_access.roles → ROLE_* authorities; principal name = azp")
    void extractsRealmRoles() {
        Jwt jwt = jwtWith(Map.of(
                "azp", "ivy-events-be-svc",
                "realm_access", Map.of("roles", List.of("iam-client", "offline_access"))
        ));

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(auth.getName()).isEqualTo("ivy-events-be-svc");
        assertThat(authorityNames(auth.getAuthorities()))
                .contains("ROLE_iam-client", "ROLE_offline_access");
    }

    @Test
    @DisplayName("Missing realm_access → no ROLE_ authorities, no NPE")
    void noRealmAccessIsFine() {
        Jwt jwt = jwtWith(Map.of("azp", "ivy-events-be-svc"));

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(authorityNames(auth.getAuthorities()))
                .noneMatch(n -> n.startsWith("ROLE_"));
    }

    @Test
    @DisplayName("Missing azp → principal name falls back to sub")
    void fallsBackToSub() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .subject("sub-uuid-123")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(auth.getName()).isEqualTo("sub-uuid-123");
    }

    @Test
    @DisplayName("Non-list roles claim is ignored, no exception")
    void nonListRolesIgnored() {
        Jwt jwt = jwtWith(Map.of(
                "azp", "x-svc",
                "realm_access", Map.of("roles", "not-a-list")
        ));

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(authorityNames(auth.getAuthorities()))
                .noneMatch(n -> n.startsWith("ROLE_"));
    }

    private static Jwt jwtWith(Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .subject("sub")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
        claims.forEach(b::claim);
        return b.build();
    }

    private static List<String> authorityNames(Collection<? extends GrantedAuthority> a) {
        return a.stream().map(GrantedAuthority::getAuthority).toList();
    }
}
