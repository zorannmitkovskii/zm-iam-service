package zm.iam.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

/**
 * Default {@link AuditService} — inserts an {@link AuditLogEntry} on a
 * Spring async executor. Fires-and-forgets: a DB error logs at ERROR,
 * bumps {@code iam_audit_failures_total}, and returns. The main caller
 * never sees the failure.
 *
 * <p>{@code @Transactional(propagation = REQUIRES_NEW)} isolates the
 * audit write from any transaction the caller might be in. A rolled-
 * back business transaction still leaves its audit trail behind — the
 * whole point of "what happened".
 *
 * <p>All PII sanitisation runs synchronously before the async submit,
 * so if a caller ever accidentally passed raw values the exception
 * (unlikely, but possible for a null in a forbidden key) surfaces in
 * their thread rather than as a mysterious background ERROR.
 */
@Slf4j
@Service
public class DbAuditService implements AuditService {

    private final AuditLogRepository repository;
    private final ObjectMapper canonical;
    private final Counter failuresCounter;

    public DbAuditService(AuditLogRepository repository,
                          @Qualifier("manifestCanonicalMapper") ObjectMapper canonical,
                          MeterRegistry meters) {
        this.repository = repository;
        this.canonical = canonical;
        this.failuresCounter = Counter.builder("iam_audit_failures_total")
                .description("Audit inserts that failed after all retries. "
                        + "Non-zero => data loss in the audit trail; investigate immediately.")
                .register(meters);
    }

    @Override
    @Async("auditTaskExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEvent event) {
        try {
            var sanitisedDetail = PiiMasker.sanitiseDetail(event.detail());
            AuditLogEntry row = AuditLogEntry.builder()
                    .occurredAt(OffsetDateTime.now())
                    .caller(event.caller())
                    .realm(event.realm())
                    .targetType(event.targetType())
                    .targetId(event.targetId())
                    .operation(event.operation())
                    .detail(canonical.valueToTree(sanitisedDetail))
                    .success(event.success())
                    .build();
            repository.save(row);
        } catch (RuntimeException e) {
            // Never let the audit path throw back into the caller — that
            // path is @Async so the exception would be swallowed anyway,
            // but the counter + ERROR log make it visible to ops.
            failuresCounter.increment();
            log.error("[Audit] DB insert failed for event {} — {}: {}",
                    event.short_(), e.getClass().getSimpleName(), e.getMessage(), e);
        }
    }
}
