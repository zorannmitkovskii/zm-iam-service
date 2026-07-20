package zm.iam.user.dto;

import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * Body of {@code PUT /internal/users/{id}/roles} — declarative set of
 * realm role NAMES the user should have. Empty list = remove all
 * realm roles. IAM computes add / remove diff against the user's
 * current realm-level roles.
 */
public record RolesPutDto(
        @NotNull List<@jakarta.validation.constraints.NotBlank String> roles
) {}
