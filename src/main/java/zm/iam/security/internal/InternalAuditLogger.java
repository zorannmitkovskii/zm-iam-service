package zm.iam.security.internal;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Log-only audit trail for {@code /internal/**} authorization decisions.
 * Same shape as {@code AuthAuditLogger} from IAM-05 (single-line,
 * grep-friendly, stable field order) so a future audit-table migration
 * (IAM-11) can absorb both event streams into one table without
 * dictionary work.
 *
 * <p>Never logs the raw JWT — only the {@code azp} claim (already a
 * client id, not a secret) and the derived serviceId.
 */
@Slf4j
@Component
public class InternalAuditLogger {

    public enum Decision {
        ALLOWED,
        DENIED_MISSING_AZP,
        DENIED_BAD_AZP,
        DENIED_MISSING_REALM_PARAM,
        DENIED_REALM_NOT_OWNED
    }

    public void audit(Decision decision,
                      String azp,
                      String serviceId,
                      String requestedRealm,
                      String method,
                      String path,
                      String ownerOfRealm) {
        log.info("[InternalAudit] decision={} azp={} serviceId={} realm={} method={} path={} realmOwner={}",
                decision.name(),
                nullSafe(azp),
                nullSafe(serviceId),
                nullSafe(requestedRealm),
                nullSafe(method),
                nullSafe(path),
                nullSafe(ownerOfRealm));
    }

    private static String nullSafe(String s) { return s == null ? "-" : s; }
}
