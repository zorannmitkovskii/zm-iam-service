package zm.iam.provisioning;

import lombok.Getter;
import zm.iam.provisioning.reconcile.ChangeEntry;

import java.util.List;

/**
 * Raised when a reconciler step fails mid-apply. Carries the list of
 * steps that ran successfully BEFORE the failure so the API can help the
 * operator see how far the chain got.
 *
 * <p>Because {@code ProvisioningService.apply} is {@code @Transactional},
 * throwing this rolls back the DB write — {@code applied_manifests}
 * stays clean, and a retry with the same version after fixing the
 * underlying issue is safe.
 */
@Getter
public class ProvisioningFailedException extends RuntimeException {
    private final List<ChangeEntry> appliedSteps;

    public ProvisioningFailedException(String message, List<ChangeEntry> appliedSteps, Throwable cause) {
        super(message, cause);
        this.appliedSteps = List.copyOf(appliedSteps);
    }
}
