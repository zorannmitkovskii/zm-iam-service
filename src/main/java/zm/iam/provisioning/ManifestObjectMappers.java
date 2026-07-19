package zm.iam.provisioning;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Provisioning-manifest-scoped Jackson mappers. Separate from Spring
 * Boot's global {@link ObjectMapper} because manifests have STRICTER
 * rules than a normal REST payload:
 * <ul>
 *   <li>{@code FAIL_ON_UNKNOWN_PROPERTIES=true} — a typo like
 *       {@code multiValued} vs {@code multivalued} must be a 400, not a
 *       silently-ignored field. Also catches attempts to sneak a plain
 *       {@code clientSecret} into an IdP declaration.</li>
 *   <li>Canonical serialisation — keys sorted alphabetically — so
 *       {@link zm.iam.provisioning.hashing.ManifestHasher} produces
 *       the same hash regardless of YAML key order.</li>
 * </ul>
 */
@Configuration
public class ManifestObjectMappers {

    /** Strict JSON mapper for reading manifest bodies coming in over
     *  HTTP as {@code application/json}.
     *
     *  <p>{@code defaultCandidate=false} keeps this bean out of the
     *  autowire pool for un-qualified {@code ObjectMapper} injections —
     *  Spring's default mapper stays the primary choice for global uses
     *  like {@link zm.iam.keycloak.KeycloakAdminSession}. */
    @Bean(name = "manifestJsonMapper", defaultCandidate = false)
    public ObjectMapper manifestJsonMapper() {
        return strict(new ObjectMapper());
    }

    /** Strict YAML mapper for reading manifest bodies as
     *  {@code application/yaml} or when a service loads its own
     *  {@code src/main/resources/iam-manifest.yml}. */
    @Bean(name = "manifestYamlMapper", defaultCandidate = false)
    public ObjectMapper manifestYamlMapper() {
        return strict(new ObjectMapper(new YAMLFactory()));
    }

    /** Canonical mapper — used ONLY for hashing. Keys sorted, empty
     *  values elided so cosmetic edits don't change the digest. */
    @Bean(name = "manifestCanonicalMapper", defaultCandidate = false)
    public ObjectMapper manifestCanonicalMapper() {
        ObjectMapper m = new ObjectMapper();
        m.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        m.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
        m.configure(SerializationFeature.INDENT_OUTPUT, false);
        m.setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);
        return m;
    }

    private static ObjectMapper strict(ObjectMapper m) {
        m.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        m.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);
        m.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, false);
        return m;
    }
}
