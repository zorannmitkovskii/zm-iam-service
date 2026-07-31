package zm.iam.publicauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /public/users/change-password — self-serve password change for a user
 * who can still prove the current password. Public (no JWT) because the
 * caller of this flow is a browser that has just logged in with a temporary
 * password and carries no usable token yet.
 */
public record ChangePasswordRequest(
        @NotBlank @Email String email,
        @NotBlank String currentPassword,
        @NotBlank @Size(min = 8) String newPassword,
        /** Optional — used if Origin header can't resolve to a realm. */
        String appId
) {}
