package zm.iam.provisioning;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Parses + validates a raw manifest body (JSON or YAML) into a fully
 * validated {@link ServiceProvisioningManifest}. Two-step so callers can
 * distinguish "malformed body" from "structurally-well-formed but
 * business-invalid".
 *
 * <p>Uses the strict manifest-scoped mappers (see
 * {@link ManifestObjectMappers}) — unknown properties fail the parse,
 * which is the mechanism enforcing "no plaintext secrets in an IdP
 * block" (ticket §Acceptance Criteria #4).
 */
@Component
public class ManifestParser {

    private final ObjectMapper jsonMapper;
    private final ObjectMapper yamlMapper;
    private final Validator validator;

    public ManifestParser(@Qualifier("manifestJsonMapper") ObjectMapper jsonMapper,
                          @Qualifier("manifestYamlMapper") ObjectMapper yamlMapper,
                          Validator validator) {
        this.jsonMapper = jsonMapper;
        this.yamlMapper = yamlMapper;
        this.validator = validator;
    }

    /**
     * Parse + validate. Any structural failure surfaces as a
     * {@link com.fasterxml.jackson.core.JsonProcessingException} — bubble
     * up to Spring's HttpMessageNotReadableException handling. Any Bean
     * Validation failure surfaces as {@link ConstraintViolationException}.
     */
    public ServiceProvisioningManifest parseAndValidate(String rawBody, MediaType contentType) throws Exception {
        ObjectMapper mapper = isYaml(contentType) ? yamlMapper : jsonMapper;
        ServiceProvisioningManifest manifest;
        try {
            manifest = mapper.readValue(rawBody, ServiceProvisioningManifest.class);
        } catch (UnrecognizedPropertyException e) {
            // Wrap so callers can rely on a single "malformed" exception
            // regardless of which strict rule fired.
            throw new IllegalArgumentException(
                    "Unknown property '" + e.getPropertyName() + "' at "
                            + e.getPathReference(), e);
        } catch (MismatchedInputException e) {
            throw new IllegalArgumentException(
                    "Type mismatch at " + e.getPathReference() + ": " + e.getOriginalMessage(), e);
        }

        Set<ConstraintViolation<ServiceProvisioningManifest>> violations = validator.validate(manifest);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
        return manifest;
    }

    private static boolean isYaml(MediaType contentType) {
        if (contentType == null) return false;
        String type = contentType.toString().toLowerCase();
        return type.contains("yaml") || type.contains("yml");
    }
}
