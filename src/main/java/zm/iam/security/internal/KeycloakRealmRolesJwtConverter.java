package zm.iam.security.internal;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Keycloak-flavoured JWT authorities converter. The default
 * {@link JwtGrantedAuthoritiesConverter} only reads {@code scope}/
 * {@code scp}; Keycloak puts realm roles in
 * {@code realm_access.roles}, which is what SelfBootstrap (IAM-02)
 * assigns to every service account via the {@code iam-client} role.
 *
 * <p>Output authorities: {@code SCOPE_*} for OAuth scopes (kept for
 * consistency with other Spring resource servers) PLUS
 * {@code ROLE_<realmRole>} entries so {@code hasRole("iam-client")}
 * on the security config just works.
 *
 * <p>Client roles ({@code resource_access.<client>.roles}) are
 * intentionally NOT translated — IAM's authz model uses realm roles
 * only, and pulling client roles into the authority set would risk
 * collisions between different clients that happen to share a role
 * name.
 */
@Slf4j
public class KeycloakRealmRolesJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>(scopeConverter.convert(jwt));
        for (String role : realmRoles(jwt)) {
            // ROLE_ prefix matches Spring Security's hasRole() default —
            // hasRole("iam-client") maps to "ROLE_iam-client".
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        // Principal name = azp (the calling service account client id).
        // Falls back to `sub` when azp is absent (should not happen for
        // client_credentials tokens but keep the default sane).
        String name = jwt.getClaimAsString("azp");
        if (name == null) name = jwt.getSubject();
        return new JwtAuthenticationToken(jwt, authorities, name);
    }

    @SuppressWarnings("unchecked")
    private static List<String> realmRoles(Jwt jwt) {
        Object claim = jwt.getClaims().get("realm_access");
        if (!(claim instanceof Map<?, ?> map)) return List.of();
        Object roles = map.get("roles");
        if (!(roles instanceof List<?> list)) return List.of();
        List<String> out = new ArrayList<>(list.size());
        for (Object r : list) {
            if (r instanceof String s) out.add(s);
        }
        return out;
    }
}
