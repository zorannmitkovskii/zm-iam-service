package zm.iam.keycloak;

import lombok.Getter;

/**
 * Thrown when a Keycloak Admin call returns a non-2xx we care about
 * propagating specifically (409 duplicate, 400 validation, etc). The
 * status code lets callers pattern-match without parsing the message.
 */
@Getter
public class KeycloakApiException extends RuntimeException {
    private final int status;

    public KeycloakApiException(String message, int status) {
        super(message);
        this.status = status;
    }
}
