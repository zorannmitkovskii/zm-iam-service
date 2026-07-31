package zm.iam.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import zm.iam.publicauth.PublicAuthProperties;

import java.util.List;

/**
 * CORS for the public-auth chain. A frontend posts its login and registration
 * forms straight to IAM from its own origin, so the browser sends a preflight
 * that has to be answered here.
 *
 * <p>The allowed origins are derived from
 * {@link PublicAuthProperties#getOriginToRealm()} rather than configured
 * separately. Those two lists have to agree — an origin that passes CORS but
 * maps to no realm gets a 400 it cannot explain, and an origin that maps to a
 * realm but fails CORS never arrives at all. Deriving one from the other means
 * adding a frontend is a single entry.
 *
 * <p>No wildcard, and credentials stay off: the flows here carry credentials in
 * the body and hand tokens back in the body. Nothing depends on cookies.
 */
@Configuration
public class PublicAuthCorsConfig {

    /** Mapping keys may be {@code host:port} or a bare {@code host}; both are
     *  expanded to the two schemes a browser can send. */
    private static final List<String> SCHEMES = List.of("http://", "https://");

    @Bean
    public CorsConfigurationSource publicAuthCorsSource(PublicAuthProperties props) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(props.getOriginToRealm().keySet().stream()
                .flatMap(host -> SCHEMES.stream().map(scheme -> scheme + host))
                .toList());
        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/public/**", config);
        return source;
    }
}
