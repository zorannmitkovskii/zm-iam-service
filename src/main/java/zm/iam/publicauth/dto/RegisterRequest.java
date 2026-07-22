package zm.iam.publicauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** POST /public/users/register — creates a disabled user + issues a 6-digit
 *  verification code + emails it. Same shape as ivy-events-be today. */
public record RegisterRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8) String password,
        String firstName,
        String lastName,
        /** Optional — used if Origin header can't resolve to a realm. */
        String appId
) {}
