package zm.iam.publicauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/** POST /public/auth/password-reset/request — issues a 6-digit code, emails it. */
public record PasswordResetRequestDto(
        @NotBlank @Email String email,
        String appId
) {}
