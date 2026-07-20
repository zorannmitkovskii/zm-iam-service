package zm.iam.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.util.List;
import java.util.Map;

/**
 * Body of {@code POST /internal/users}. Mirrors the shape
 * ivy-events-be's {@code KeycloakUserService} accepts today so
 * IVY-BE-02's migration is a straight controller-swap.
 *
 * <p>{@code temporaryPassword} is optional; when present, IAM sets it
 * with {@code temporary=true} so Keycloak forces the
 * {@code UPDATE_PASSWORD} required action on first login — same UX as
 * the current admin-created flow.
 */
public record UserCreateDto(
        @NotBlank @Email String email,
        String firstName,
        String lastName,
        Boolean enabled,
        Map<String, List<String>> attributes,
        String temporaryPassword,
        List<String> realmRoles
) {}
