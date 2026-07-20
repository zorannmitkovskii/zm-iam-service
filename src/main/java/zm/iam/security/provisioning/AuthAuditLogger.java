package zm.iam.security.provisioning;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Log-only audit trail for provisioning-endpoint authentication
 * decisions. Purposely single-line and grep-friendly. Never logs the
 * plaintext token or the argon2 hash — only length and presence markers.
 *
 * <p>Migrates to an audit table (IAM-11) — keep the fields stable so the
 * eventual schema can pull them straight out of logs.
 */
@Slf4j
@Component
public class AuthAuditLogger {

    public enum Decision {
        ALLOWED,
        DENIED_MISSING_HEADER,
        DENIED_TOKEN_INVALID,
        DENIED_SERVICEID_MISMATCH,
        DENIED_UNKNOWN_SERVICE,
        RATE_LIMITED
    }

    public void audit(Decision decision,
                      String serviceIdFromToken,
                      String serviceIdFromRequest,
                      String clientIp,
                      String path,
                      int tokenHeaderLength) {
        log.info("[ProvisioningAudit] decision={} tokenServiceId={} requestServiceId={} clientIp={} path={} tokenLen={}",
                decision.name(),
                nullSafe(serviceIdFromToken),
                nullSafe(serviceIdFromRequest),
                nullSafe(clientIp),
                nullSafe(path),
                tokenHeaderLength);
    }

    private static String nullSafe(String s) { return s == null ? "-" : s; }
}
