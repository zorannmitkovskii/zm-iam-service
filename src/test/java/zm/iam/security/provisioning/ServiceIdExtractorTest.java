package zm.iam.security.provisioning;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ServiceIdExtractorTest {

    private final ServiceIdExtractor extractor = new ServiceIdExtractor(new ObjectMapper());

    @Test
    @DisplayName("GET /provisioning/manifests/{serviceId} → serviceId from path")
    void extractsFromPath() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn("/provisioning/manifests/ivy-events-be");
        assertThat(extractor.extract(req, null)).contains("ivy-events-be");
    }

    @Test
    @DisplayName("POST /provisioning/manifests → serviceId from body")
    void extractsFromBody() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRequestURI()).thenReturn("/provisioning/manifests");
        byte[] body = "{\"serviceId\":\"presmetko-be\",\"manifestVersion\":1}"
                .getBytes(StandardCharsets.UTF_8);
        assertThat(extractor.extract(req, body)).contains("presmetko-be");
    }

    @Test
    @DisplayName("Malformed body → empty")
    void malformedBodyIsEmpty() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRequestURI()).thenReturn("/provisioning/manifests");
        assertThat(extractor.extract(req, "not json".getBytes(StandardCharsets.UTF_8))).isEmpty();
    }

    @Test
    @DisplayName("Unknown path → empty")
    void unknownPathIsEmpty() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRequestURI()).thenReturn("/actuator/health");
        assertThat(extractor.extract(req, null)).isEmpty();
    }
}
