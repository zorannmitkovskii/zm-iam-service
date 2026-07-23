package zm.iam.publicauth.dto;

import jakarta.validation.constraints.NotBlank;

/** POST /public/users/login — password grant against the resolved realm.
 *  The identifier is the Keycloak username (which is the user's email in
 *  every realm we run). */
public record LoginRequest(
        @NotBlank String username,
        @NotBlank String password,
        String appId
) {}
