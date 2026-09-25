package zm.iam.provisioning;

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;
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
        return strict(JsonMapper.builder()).build();
    }

    /** Strict YAML mapper for reading manifest bodies as
     *  {@code application/yaml} or when a service loads its own
     *  {@code src/main/resources/iam-manifest.yml}. */
    @Bean(name = "manifestYamlMapper", defaultCandidate = false)
    public ObjectMapper manifestYamlMapper() {
        return strict(YAMLMapper.builder()).build();
    }

    /** Canonical mapper — used ONLY for hashing. Keys sorted, empty
     *  values elided so cosmetic edits don't change the digest. */
    @Bean(name = "manifestCanonicalMapper", defaultCandidate = false)
    public ObjectMapper manifestCanonicalMapper() {
        // withValueInclusion rather than the ALL_NON_NULL constant: the old
        // setSerializationInclusion set the value inclusion only. ALL_NON_NULL
        // would also elide nulls inside maps and lists, which changes the
        // bytes — and these bytes are what the digest is taken over.
        return JsonMapper.builder()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .configure(SerializationFeature.INDENT_OUTPUT, false)
                .changeDefaultPropertyInclusion(v -> v.withValueInclusion(JsonInclude.Include.NON_NULL))
                .build();
    }

    /**
     * The strict settings, applied to whichever builder is handed in.
     *
     * <p>Generic over the builder rather than taking a mapper: Jackson 3's
     * ObjectMapper is immutable, so settings can only be applied before the
     * build. The recursive bound is what lets one method serve both the JSON
     * and the YAML builder and still return the caller's own type.
     */
    private static <B extends MapperBuilder<?, B>> B strict(B builder) {
        return builder
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
                .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, false);
    }
}
