package zm.iam.provisioning.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * External identity provider (social login etc.). Secrets NEVER travel in
 * the manifest — the fields end with {@code EnvRef} and hold the NAME of
 * the environment variable IAM must read locally to obtain the actual
 * credential. Manifest stays log-safe.
 *
 * <p>Extra JSON properties are rejected — protects against a caller
 * mistakenly sending a plaintext {@code clientSecret} field, which is a
 * hard-fail security requirement (ticket §Acceptance Criteria #4).
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record IdentityProviderDeclaration(
        @NotBlank(message = "alias is required")
        String alias,

        @NotBlank(message = "type is required")
        String type,

        @NotBlank(message = "clientIdEnvRef is required — never a raw client id")
        @Pattern(regexp = "[A-Z][A-Z0-9_]*",
                message = "envRef must be UPPER_SNAKE_CASE (matches env-var convention)")
        String clientIdEnvRef,

        @NotBlank(message = "clientSecretEnvRef is required — secrets do not travel in manifests")
        @Pattern(regexp = "[A-Z][A-Z0-9_]*",
                message = "envRef must be UPPER_SNAKE_CASE (matches env-var convention)")
        String clientSecretEnvRef
) {
}
