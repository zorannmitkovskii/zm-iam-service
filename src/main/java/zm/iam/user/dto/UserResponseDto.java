package zm.iam.user.dto;

import java.util.List;
import java.util.Map;

/**
 * Read-model returned by GET / POST / PATCH. Fields chosen to match the
 * response ivy-events-be's {@code KeycloakUserService} currently returns,
 * so downstream JSON parsing doesn't need to change (see AC 8 of the
 * ticket).
 */
public record UserResponseDto(
        String id,
        String email,
        String firstName,
        String lastName,
        boolean enabled,
        Map<String, List<String>> attributes,
        List<String> realmRoles
) {}
