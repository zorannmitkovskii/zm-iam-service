package zm.iam.common;

import org.hibernate.cfg.MappingSettings;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;

/**
 * Points Hibernate's {@code jsonb} handling at Jackson 3.
 *
 * <p>Set as an instance rather than a class name: the mapper needs the
 * application's configured {@link ObjectMapper}, and Hibernate instantiating it
 * reflectively would give it one built from defaults.
 */
@Configuration
public class HibernateJsonConfig {

    @Bean
    public HibernatePropertiesCustomizer jackson3JsonFormatMapper(ObjectMapper objectMapper) {
        return properties -> properties.put(
                MappingSettings.JSON_FORMAT_MAPPER, new Jackson3JsonFormatMapper(objectMapper));
    }
}
