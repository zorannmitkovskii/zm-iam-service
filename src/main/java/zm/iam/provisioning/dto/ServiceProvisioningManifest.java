package zm.iam.provisioning.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Objects;

/**
 * The declarative source of truth a service ships to IAM to describe the
 * Keycloak state it wants to exist. IAM-03 covers only the model + rules;
 * the reconciler that applies the manifest lands in IAM-04.
 *
 * <p>Two class-level rules are enforced via {@link AssertTrue} rather than
 * separate ConstraintValidator classes because they read directly off the
 * record's own state — no external context needed:
 * <ul>
 *   <li>Realm names must be unique across the manifest.</li>
 *   <li>In the shared {@code zm-services} realm, only clients whose
 *       {@code clientId} equals {@code {serviceId}-svc} are allowed —
 *       prevents a service from squatting on another's namespace.</li>
 * </ul>
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record ServiceProvisioningManifest(
        @NotBlank(message = "serviceId is required")
        @Pattern(regexp = "[a-z0-9-]+",
                message = "serviceId must match [a-z0-9-]+")
        @Size(max = 64, message = "serviceId must be ≤ 64 characters")
        String serviceId,

        @Positive(message = "manifestVersion must be a positive integer")
        int manifestVersion,

        @NotEmpty(message = "at least one realm must be declared")
        @Valid
        List<RealmDeclaration> realms
) {
    /** Shared internal realm name — IAM owns this realm; other services
     *  may only declare their own {@code {serviceId}-svc} client in it. */
    public static final String ZM_SERVICES_REALM = "zm-services";

    /** {@link JsonIgnore} so Jackson doesn't emit these boolean assertion
     *  methods as extra fields when we canonicalise the manifest for
     *  persistence — the round-trip would then fail with an
     *  UnrecognizedPropertyException on read. */
    @JsonIgnore
    @AssertTrue(message = "realm names must be unique across the manifest")
    public boolean isRealmNamesUnique() {
        if (realms == null) return true;
        long distinct = realms.stream()
                .map(RealmDeclaration::name)
                .filter(Objects::nonNull)
                .distinct()
                .count();
        return distinct == realms.stream()
                .map(RealmDeclaration::name)
                .filter(Objects::nonNull)
                .count();
    }

    @JsonIgnore
    @AssertTrue(message = "in zm-services realm only clients with clientId == '{serviceId}-svc' are allowed")
    public boolean isZmServicesScopeRespected() {
        if (realms == null || serviceId == null) return true;
        String expectedSvcClient = serviceId + "-svc";
        return realms.stream()
                .filter(r -> ZM_SERVICES_REALM.equals(r.name()))
                .flatMap(r -> r.clients() == null ? java.util.stream.Stream.<ClientDeclaration>empty()
                                                  : r.clients().stream())
                .allMatch(c -> expectedSvcClient.equals(c.clientId()));
    }
}
