package zm.iam.user.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Placeholder impl for IAM-08. Writes one grep-friendly line per event.
 * Kept intentionally boring so IAM-11's DB writer can pipe the same
 * fields into a schema without renaming anything.
 */
@Slf4j
@Component
public class LoggingAuditService implements AuditService {

    @Override
    public void record(String action, String realm, String userId, String detail) {
        log.info("[UserAudit] action={} realm={} userId={} detail={}",
                action, realm, userId == null ? "-" : userId, detail == null ? "-" : detail);
    }
}
