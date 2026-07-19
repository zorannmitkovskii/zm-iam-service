package zm.iam.provisioning;

import zm.iam.provisioning.reconcile.ChangeEntry;

import java.util.List;

/**
 * Result envelope of {@code POST /provisioning/manifests}.
 *
 * @param status         APPLIED (did work) | NOOP (version already applied)
 * @param serviceId      echo of the manifest's serviceId
 * @param appliedVersion current applied version — incoming on APPLIED,
 *                       previously-latest on NOOP
 * @param changes        per-resource actions; empty on NOOP
 */
public record ApplyResult(
        Status status,
        String serviceId,
        int appliedVersion,
        List<ChangeEntry> changes
) {
    public enum Status { APPLIED, NOOP }
}
