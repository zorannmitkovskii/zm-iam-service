package zm.iam.provisioning.ownership;

import lombok.Getter;

import java.util.List;

/**
 * Raised from {@link OwnershipService#check} when a caller tries to
 * touch resources owned by another service. Carries EVERY conflict at
 * once (not just the first) so the operator can fix them in one pass.
 *
 * <p>Bubbles up to {@link zm.iam.provisioning.ProvisioningController}'s
 * {@code @ExceptionHandler} which maps it to a 409 with a structured
 * body. Because the whole check runs BEFORE any reconciler write, the
 * transaction rollback leaves Keycloak completely undisturbed.
 */
@Getter
public class OwnershipConflictException extends RuntimeException {
    private final List<OwnershipConflict> conflicts;

    public OwnershipConflictException(List<OwnershipConflict> conflicts) {
        super("Ownership conflict on " + conflicts.size() + " resource(s)");
        this.conflicts = List.copyOf(conflicts);
    }
}
