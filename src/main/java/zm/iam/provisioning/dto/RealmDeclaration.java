package zm.iam.provisioning.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import java.util.List;

/**
 * One realm in a service's provisioning manifest. A manifest usually has
 * two realm entries: the app realm (owned by the service) and the shared
 * {@code zm-services} realm (owned by IAM, hosts service-account clients).
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record RealmDeclaration(
        @NotBlank(message = "realm name is required")
        String name,

        @Valid
        RealmSettings settings,

        @Valid
        List<ClientDeclaration> clients,

        List<@NotBlank String> realmRoles,

        @Valid
        List<IdentityProviderDeclaration> identityProviders,

        List<@NotBlank String> userProfileAttributes
) {
}
