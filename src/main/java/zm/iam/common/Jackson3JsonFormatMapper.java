package zm.iam.common;

import org.hibernate.type.descriptor.WrapperOptions;
import org.hibernate.type.descriptor.java.JavaType;
import org.hibernate.type.format.FormatMapper;
import tools.jackson.databind.ObjectMapper;

/**
 * Reads and writes {@code jsonb} columns with Jackson 3.
 *
 * <p>Hibernate 7 ships exactly one JSON format mapper and it is built on
 * Jackson 2 — {@code org.hibernate.type.format.jackson.JacksonJsonFormatMapper}.
 * This service moved to Jackson 3, so {@code AuditLogEntry.detail} and the two
 * {@code AppliedManifest} columns are {@code tools.jackson.databind.JsonNode},
 * a type that mapper cannot construct. Every read of an audit row or an applied
 * manifest failed with "Could not deserialize string to java type", which reads
 * like a corrupt column rather than two Jackson versions in one process.
 *
 * <p>Registered in {@link HibernateJsonConfig}. It can go the day Hibernate
 * ships a Jackson 3 mapper of its own.
 */
public final class Jackson3JsonFormatMapper implements FormatMapper {

    private final ObjectMapper objectMapper;

    public Jackson3JsonFormatMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public <T> T fromString(CharSequence charSequence, JavaType<T> javaType, WrapperOptions options) {
        // A String-typed column holds the JSON document as text. Parsing it
        // would hand back the parsed value where the caller asked for the
        // characters — Hibernate's own mapper makes the same exception.
        if (javaType.getJavaTypeClass() == String.class) {
            return javaType.getJavaTypeClass().cast(charSequence.toString());
        }
        return objectMapper.readValue(charSequence.toString(),
                objectMapper.constructType(javaType.getJavaType()));
    }

    @Override
    public <T> String toString(T value, JavaType<T> javaType, WrapperOptions options) {
        if (javaType.getJavaTypeClass() == String.class) {
            return (String) value;
        }
        return objectMapper.writeValueAsString(value);
    }
}
