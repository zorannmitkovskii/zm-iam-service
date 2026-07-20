package zm.iam.audit;

/**
 * Contract for audit sinks. IAM-11 provides {@link DbAuditService} as
 * the default implementation; tests can swap in an in-memory recorder
 * without touching the callers.
 *
 * <p>Contract:
 * <ul>
 *   <li>Never throws — audit is a side-effect, not a business
 *       operation. A DB failure must not surface to the caller.</li>
 *   <li>Never blocks longer than a queue submit — implementations run
 *       the actual insert asynchronously.</li>
 * </ul>
 */
public interface AuditService {

    void record(AuditEvent event);
}
