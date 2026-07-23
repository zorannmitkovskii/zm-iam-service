package zm.iam.publicauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Real transactional-email sender backed by the ZeptoMail HTTP API
 * ({@code POST {base}/v1.1/email}). Same wire shape as ivy-events-be's
 * ZeptoMailService, ported to IAM's {@link java.net.http.HttpClient} style.
 *
 * <p>Bean name is {@code zeptoMailEmailSender} on purpose so it wins over
 * {@link LoggingEmailSender}'s {@code @ConditionalOnMissingBean(name =
 * "zeptoMailEmailSender")}. Active by default; set
 * {@code iam.email.zepto.enabled=false} (local dev) to fall back to logging.
 */
@Slf4j
@Component("zeptoMailEmailSender")
@ConditionalOnProperty(prefix = "iam.email.zepto", name = "enabled",
        havingValue = "true", matchIfMissing = true)
public class ZeptoMailEmailSender implements EmailSender {

    private final ZeptoMailProperties props;
    private final ObjectMapper mapper;
    private final HttpClient http;

    public ZeptoMailEmailSender(ZeptoMailProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @Override
    public void send(String realm, String toEmail, EmailTemplate template) {
        if (!StringUtils.hasText(props.getToken())) {
            throw new IllegalStateException("ZeptoMail token not configured (iam.email.zepto.token)");
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(trimTrailingSlash(props.getBaseUrl()) + "/v1.1/email"))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", props.getToken())
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(buildPayload(toEmail, template)))
                .build();

        HttpResponse<String> resp;
        try {
            resp = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new IllegalStateException("ZeptoMail network failure: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while sending email", e);
        }

        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            log.error("[EmailSender/Zepto] Send FAILED status={} to={} body={}",
                    resp.statusCode(), toEmail, snippet(resp.body()));
            throw new IllegalStateException("ZeptoMail returned " + resp.statusCode());
        }
        log.info("[EmailSender/Zepto] Sent '{}' to {} (realm={})", template.subject(), toEmail, realm);
    }

    private String buildPayload(String toEmail, EmailTemplate template) {
        String htmlBody = "<p>" + escapeHtml(template.body()).replace("\n", "<br>") + "</p>";
        Map<String, Object> body = Map.of(
                "from", Map.of("address", props.getFromAddress(), "name", props.getFromName()),
                "to", List.of(Map.of("email_address", Map.of("address", toEmail))),
                "subject", template.subject(),
                "htmlbody", htmlBody);
        try {
            return mapper.writeValueAsString(body);
        } catch (Exception e) {
            throw new IllegalStateException("Could not serialise ZeptoMail payload", e);
        }
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String snippet(String s) {
        if (s == null) return "<null>";
        return s.length() > 300 ? s.substring(0, 300) + "…" : s;
    }
}
