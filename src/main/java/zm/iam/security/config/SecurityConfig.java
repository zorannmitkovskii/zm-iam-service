package zm.iam.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import zm.iam.security.provisioning.ProvisioningAuthenticationFilter;

/**
 * IAM-05 filter chain:
 * <ul>
 *   <li>{@code /provisioning/**} → {@link ProvisioningAuthenticationFilter}
 *       must succeed. On failure the filter writes its own 401/403/429/400
 *       body (matches the ApiResponse shape), so Spring Security's default
 *       entry-point is not invoked here.</li>
 *   <li>{@code /actuator/health/**} + {@code /actuator/info} + Prometheus
 *       stay open for K8s / oncall.</li>
 *   <li>Everything else denied until IAM-09 (internal JWT) lands. This
 *       is a deliberate lockdown — undeclared paths should not accidentally
 *       be reachable while auth is still being built out.</li>
 * </ul>
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           ProvisioningAuthenticationFilter provisioningFilter) throws Exception {
        http
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
                        // Locked by default — every new endpoint must be
                        // explicitly opened above.
                        .anyRequest().denyAll())
                // Put our filter BEFORE UsernamePasswordAuthenticationFilter
                // so the SecurityContext is populated before authorisation
                // runs. It handles its own error responses; Spring
                // Security's default entry-point never fires for
                // /provisioning/**.
                .addFilterBefore(provisioningFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
