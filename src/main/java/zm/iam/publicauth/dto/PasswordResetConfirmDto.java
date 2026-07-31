package zm.iam.publicauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** POST /public/auth/password-reset/confirm — validates code + sets new password. */
public record PasswordResetConfirmDto(
        @NotBlank @Email String email,
        @NotBlank @Pattern(regexp = "\\d{6}") String code,
        @NotBlank @Size(min = 8) String newPassword,
        String appId
) {}
