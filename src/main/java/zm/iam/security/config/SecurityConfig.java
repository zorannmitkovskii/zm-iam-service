package zm.iam.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import zm.iam.keycloak.config.KeycloakProperties;
import zm.iam.security.internal.KeycloakRealmRolesJwtConverter;
import zm.iam.security.internal.RealmScopeAuthorizationFilter;
import zm.iam.security.provisioning.ProvisioningAuthenticationFilter;

/**
 * Two independent Spring Security filter chains, ordered so the
 * {@code @Order} number matches the ticket that added it:
 *
 * <ol>
 *   <li><b>IAM-05 provisioning chain</b> ({@code /provisioning/**}) —
 *       delegates to {@link ProvisioningAuthenticationFilter}, which
 *       verifies an Argon2-hashed bootstrap token and writes its own
 *       error responses. Also covers {@code /actuator/health/**},
 *       {@code /actuator/info}, {@code /actuator/prometheus}, and
 *       {@code /provisioning/manifests/validate} as permitAll so K8s
 *       and CI stay green without a token.</li>
 *
 *   <li><b>IAM-09 internal JWT chain</b> ({@code /internal/**}) —
 *       {@link org.springframework.security.oauth2.jwt.JwtDecoder}
 *       validates the token against the {@code zm-services} realm
 *       issuer; {@link KeycloakRealmRolesJwtConverter} extracts realm
 *       roles so {@code hasRole("iam-client")} works;
 *       {@link RealmScopeAuthorizationFilter} enforces IAM-06's
 *       ownership contract (403 on cross-realm access).</li>
 * </ol>
 *
 * <p>Any path not matched by either chain is denied by default (fall-
 * through denyAll on the internal chain). Adding a new endpoint means
 * making an explicit permitAll or hasRole decision — accidental exposure
 * is impossible.
 */
@Configuration
public class SecurityConfig {

    // ── Provisioning chain (IAM-05) ────────────────────────────────
    @Bean
    @Order(1)
    public SecurityFilterChain provisioningFilterChain(HttpSecurity http,
                                                       ProvisioningAuthenticationFilter provisioningFilter) throws Exception {
        http
                // Scope this chain to just the paths it authenticates.
                // The other chain (internal JWT) picks up /internal/**.
                .securityMatcher("/provisioning/**", "/actuator/**")
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health/**", "/actuator/info", "/actuator/prometheus").permitAll()
                        // Dry-run validate is stateless: parse + validate
                        // + hash. Never touches Keycloak or persistence.
                        // Safe to leave open so a developer can sanity-
                        // check a manifest before shipping it.
                        .requestMatchers("/provisioning/manifests/validate").permitAll()
                        .requestMatchers("/provisioning/**").hasRole("PROVISIONING")
                        .anyRequest().denyAll())
                // Put our filter BEFORE UsernamePasswordAuthenticationFilter
                // so the SecurityContext is populated before authorisation
                // runs. It handles its own error responses; Spring
                // Security's default entry-point never fires for
                // /provisioning/**.
                .addFilterBefore(provisioningFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // ── Internal JWT chain (IAM-09) ────────────────────────────────
    @Bean
    @Order(2)
    public SecurityFilterChain internalFilterChain(HttpSecurity http,
                                                   RealmScopeAuthorizationFilter realmScopeFilter) throws Exception {
        http
                .securityMatcher("/internal/**")
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Every /internal/** endpoint requires the
                        // iam-client realm role. Ownership is enforced
                        // by the realm-scope filter downstream.
                        .anyRequest().hasRole("iam-client"))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(new KeycloakRealmRolesJwtConverter())))
                // Runs AFTER Spring's AuthorizationFilter, which means
                // authentication + role check have already passed.
                // Purpose: enforce ownership scoping — 403 if the
                // service tries to touch a realm it doesn't own.
                .addFilterAfter(realmScopeFilter, AuthorizationFilter.class);
        return http.build();
    }

    // ── IAM-10 public auth chain ───────────────────────────────────
    // No JWT, no bootstrap token — these are the flows a browser hits
    // BEFORE it has any credentials. Every endpoint here is throttled
    // (rate limiter) and validated (verification codes, Origin→realm
    // mapping) at the service layer.
    @Bean
    @Order(3)
    public SecurityFilterChain publicAuthFilterChain(
            HttpSecurity http,
            CorsConfigurationSource publicAuthCorsSource) throws Exception {
        http
                .securityMatcher("/public/**")
                .csrf(AbstractHttpConfigurer::disable)
                // Browsers reach this chain directly — a frontend posts its
                // login form here from its own origin — so CORS is answered
                // here rather than assumed to come from a proxy in front.
                // Allowed origins are configured, never wildcarded: the same
                // Origin header picks the Keycloak realm downstream, so
                // accepting an unknown one is not a preflight detail.
                .cors(cors -> cors.configurationSource(publicAuthCorsSource))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    // ── Default deny-all catch-all ─────────────────────────────────
    // Any request that matched none of the three chains above lands
    // here and is refused. This is our safety net against future
    // controllers being added without a matching security rule.
    @Bean
    @Order(4)
    public SecurityFilterChain denyAllFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().denyAll());
        return http.build();
    }

    /**
     * JwtDecoder pointed at the {@code zm-services} realm on our
     * Keycloak. Uses issuer-location discovery so key rotations are
     * handled automatically; no need to bake JWKS URLs into config.
     *
     * <p>The bean is defined here (rather than in application.yml) so
     * we can compose the issuer URL from the existing KeycloakProperties
     * fields without duplicating base-url in a new
     * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}
     * property. Overridable via
     * {@code iam.security.internal.issuer-uri} for tests / private
     * networks where the discovery URL differs from the token issuer.
     */
    @Bean
    public JwtDecoder jwtDecoder(KeycloakProperties keycloak,
                                 @Value("${iam.security.internal.issuer-uri:#{null}}") String override) {
        // SupplierJwtDecoder defers the discovery HTTP call until the
        // first token is validated. Without this, startup would fail
        // in any environment that boots without a reachable Keycloak
        // (unit tests, docker-compose stages before Keycloak is up,
        // etc.) because JwtDecoders.fromIssuerLocation hits
        // {issuer}/.well-known/openid-configuration eagerly.
        return new SupplierJwtDecoder(() -> {
            String issuer = override != null && !override.isBlank()
                    ? override
                    : keycloak.getBaseUrl().replaceAll("/+$", "")
                            + "/realms/" + keycloak.getZmServicesRealm();
            return JwtDecoders.fromIssuerLocation(issuer);
        });
    }
}
