package zm.iam.provisioning.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;

/**
 * A Keycloak protocol mapper that copies a user attribute into an ID/access
 * token claim. Kept intentionally narrow — only the fields we need for
 * Ivy's current usage.
 *
 * <p>Reject-on-unknown is strict here: any unrecognised YAML key produces
 * a 400. That prevents silent typos ({@code multiValued} vs
 * {@code multivalued}) from producing a mapper the operator didn't intend.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record ProtocolMapperDeclaration(
        @NotBlank(message = "protocol mapper name is required")
        String name,

        @NotBlank(message = "userAttribute is required")
        String userAttribute,

        @NotBlank(message = "claim is required")
        String claim,

        /** Nullable — defaults to false (single-valued). */
        Boolean multivalued,

        /** Optional JSON type override (e.g. "boolean", "int"). Null → String. */
        String jsonType
) {
}
