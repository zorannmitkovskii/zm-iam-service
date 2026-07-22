package zm.iam.publicauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/** POST /public/users/login — password grant against the resolved realm. */
public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank String password,
        String appId
) {}
