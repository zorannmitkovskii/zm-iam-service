package zm.iam.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

/**
 * Nightly housekeeping. Retention is a policy call — the default 365
 * days is what most jurisdictions treat as adequate for audit trails;
 * bumps to 2555 days (7 years) for financial contexts if we ever need
 * SOX-like retention.
 *
 * <p>{@code retention-days = 0} disables the job entirely (the DELETE
 * would have no cutoff and would wipe everything).
 */
@Slf4j
@Component
public class AuditRetentionJob {

    private final AuditLogRepository repository;
    private final AuditProperties props;

    public AuditRetentionJob(AuditLogRepository repository, AuditProperties props) {
        this.repository = repository;
        this.props = props;
    }

    @Scheduled(cron = "${iam.audit.retention-cron:0 15 3 * * *}")
    @Transactional
    public void purgeOldEntries() {
        if (props.getRetentionDays() <= 0) {
            log.debug("[AuditRetention] retention-days={} — skipping purge", props.getRetentionDays());
            return;
        }
        OffsetDateTime cutoff = OffsetDateTime.now().minusDays(props.getRetentionDays());
        int deleted = repository.deleteOlderThan(cutoff);
        if (deleted > 0) {
            log.info("[AuditRetention] Deleted {} audit rows older than {}", deleted, cutoff);
        } else {
            log.debug("[AuditRetention] No audit rows older than {} — nothing to delete", cutoff);
        }
    }
}
