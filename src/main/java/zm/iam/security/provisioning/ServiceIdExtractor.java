package zm.iam.security.provisioning;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Extracts the target {@code serviceId} from the request so the
 * authentication filter can compare it against the token's
 * {@code serviceId} (the one the caller PROVED with an argon2 match).
 *
 * <ul>
 *   <li>{@code GET /provisioning/manifests/{serviceId}} → path segment.</li>
 *   <li>{@code POST /provisioning/manifests} → JSON body's {@code serviceId}.</li>
 * </ul>
 *
 * <p>Body extraction is a peek — the underlying request is read via a
 * {@code ContentCachingRequestWrapper} so the controller can still
 * deserialise the same bytes downstream.
 */
@Slf4j
@Component
public class ServiceIdExtractor {

    private static final String PATH_PREFIX = "/provisioning/manifests";

    private final ObjectMapper mapper;

    public ServiceIdExtractor(@Qualifier("manifestJsonMapper") ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** {@code Optional.empty()} means "could not determine" — callers
     *  MUST treat that as a 400/403, not as "no check needed". */
    public Optional<String> extract(HttpServletRequest req, byte[] cachedBody) {
        String method = req.getMethod();
        String path = req.getRequestURI();

        if ("GET".equalsIgnoreCase(method) && path.startsWith(PATH_PREFIX + "/")) {
            String tail = path.substring(PATH_PREFIX.length() + 1);
            int slash = tail.indexOf('/');
            String segment = slash < 0 ? tail : tail.substring(0, slash);
            return segment.isBlank() ? Optional.empty() : Optional.of(segment);
        }

        if ("POST".equalsIgnoreCase(method) && path.equals(PATH_PREFIX)) {
            if (cachedBody == null || cachedBody.length == 0) return Optional.empty();
            try {
                JsonNode root = mapper.readTree(cachedBody);
                JsonNode idNode = root.get("serviceId");
                if (idNode == null || !idNode.isTextual()) return Optional.empty();
                return Optional.of(idNode.asText());
            } catch (Exception e) {
                log.debug("[ServiceIdExtractor] Body was not parseable JSON: {}", e.getMessage());
                return Optional.empty();
            }
        }
        return Optional.empty();
    }
}
