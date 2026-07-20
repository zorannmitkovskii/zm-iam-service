package zm.iam.user.dto;

import jakarta.validation.constraints.NotNull;

/** Body of {@code PUT /internal/users/{id}/enabled}. */
public record EnabledDto(@NotNull Boolean enabled) {}
