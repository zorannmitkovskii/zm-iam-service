package zm.iam.publicauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;

/**
 * Creates the organization behind an organizer account (registration).
 *
 * <p>This is a new edge — IAM did not know zm-organization-service existed
 * before, and the cost is real: identity now depends on the business registry
 * during signup. It is here rather than in the product because the account has
 * to be <b>complete</b> when the email is verified. The alternative leaves a
 * window where somebody is an organizer with no organization, and every screen
 * they open in that window is a 403 they cannot act on.
 *
 * <p>Only the name is sent. The legal details the registry can hold — tax id,
 * VAT number, address — are the owner's to fill in, and inventing them at signup
 * would put guesses into a registry other products read as fact.
 */
@Slf4j
@Component
public class OrganizationServiceClient {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final String CREATED_BY_APP = "zm-iam-service";

    private final String baseUrl;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final HttpClient httpClient;
    private final ObjectMapper mapper;

    /**
     * Builds its own {@link HttpClient} rather than injecting one: IAM declares
     * no such bean, and the two clients it already has each build their own.
     * Adding a shared bean would change how both of those behave to serve this
     * one caller.
     */
    public OrganizationServiceClient(
            @Value("${org.service.base-url:}") String baseUrl,
            @Value("${org.service.token-url:}") String tokenUrl,
            @Value("${org.service.client-id:}") String clientId,
            @Value("${org.service.client-secret:}") String clientSecret,
            ObjectMapper mapper) {

        this.baseUrl = baseUrl;
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.mapper = mapper;
        this.httpClient = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    }

    /**
     * True when there is somewhere to send the request and something to
     * authenticate with.
     *
     * <p>Unconfigured is deliberately not a startup failure. IAM serves personal
     * signups, logins and password resets perfectly well without the registry,
     * and refusing to boot would take all of that down to protect a feature
     * nobody is using yet. It becomes an error at the moment somebody actually
     * signs up as an organizer, where it can be reported to the person it
     * affects.
     */
    public boolean isConfigured() {
        return notBlank(baseUrl) && notBlank(tokenUrl) && notBlank(clientId) && notBlank(clientSecret);
    }

    /**
     * @return the new organization's id
     * @throws OrganizationServiceUnavailableException when the registry cannot
     *     be reached or refuses. Deliberately not swallowed: an organizer whose
     *     organization was never created looks signed up and is not, and finding
     *     that out at the first 403 is worse than finding it out here.
     */
    public UUID createOrganization(String name) {
        if (!isConfigured()) {
            throw new OrganizationServiceUnavailableException(
                    "Organizer signup needs org.service.{base-url,token-url,client-id,client-secret}; "
                            + "at least one is unset, so no organization can be created.", null);
        }

        String payload;
        try {
            payload = mapper.writeValueAsString(new CreateOrganization(name, CREATED_BY_APP));
        } catch (Exception e) {
            throw new OrganizationServiceUnavailableException("Could not build the request", e);
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/internal/organizations"))
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + serviceToken())
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200 && response.statusCode() != 201) {
                throw new OrganizationServiceUnavailableException(
                        "zm-organization-service answered " + response.statusCode(), null);
            }

            JsonNode id = mapper.readTree(response.body()).get("id");
            if (id == null || id.isNull()) {
                throw new OrganizationServiceUnavailableException(
                        "zm-organization-service returned no id", null);
            }
            return UUID.fromString(id.asText());

        } catch (OrganizationServiceUnavailableException e) {
            throw e;
        } catch (InterruptedException e) {
            // Restore the flag. Swallowing it leaves a thread that looks healthy
            // and will not stop when asked to.
            Thread.currentThread().interrupt();
            throw new OrganizationServiceUnavailableException("Interrupted", e);
        } catch (Exception e) {
            throw new OrganizationServiceUnavailableException(
                    "Could not reach zm-organization-service", e);
        }
    }

    /**
     * A client-credentials token for the services realm.
     *
     * <p>Fetched per call rather than cached. Organizer signups are rare — a
     * handful a day at the very most — and a cache here would be a second token
     * lifecycle to get wrong for no measurable gain.
     */
    private String serviceToken() {
        String form = "grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new OrganizationServiceUnavailableException(
                        "Could not authenticate to the services realm ("
                                + response.statusCode() + ")", null);
            }
            return mapper.readTree(response.body()).get("access_token").asText();

        } catch (OrganizationServiceUnavailableException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OrganizationServiceUnavailableException("Interrupted", e);
        } catch (Exception e) {
            throw new OrganizationServiceUnavailableException("Could not obtain a service token", e);
        }
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private record CreateOrganization(String name, String createdByApp) {
    }

    public static class OrganizationServiceUnavailableException extends RuntimeException {
        public OrganizationServiceUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
