package zm.iam.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntry, UUID> {

    /** Read endpoint's search. Any of the params may be null — the query
     *  filters only on the ones supplied. Ordering is occurred_at DESC
     *  (newest first) which is what an operator scanning the log wants. */
    @Query("SELECT a FROM AuditLogEntry a WHERE "
            + "(:realm IS NULL OR a.realm = :realm) AND "
            + "(:targetId IS NULL OR a.targetId = :targetId) AND "
            + "(:from IS NULL OR a.occurredAt >= :from) AND "
            + "(:to IS NULL OR a.occurredAt < :to) "
            + "ORDER BY a.occurredAt DESC")
    Page<AuditLogEntry> search(@Param("realm") String realm,
                                @Param("targetId") String targetId,
                                @Param("from") OffsetDateTime from,
                                @Param("to") OffsetDateTime to,
                                Pageable pageable);

    /** Retention job. Bulk DELETE — Hibernate skips the first-level
     *  cache which is what we want for a background housekeeping op. */
    @Modifying
    @Query("DELETE FROM AuditLogEntry a WHERE a.occurredAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") OffsetDateTime cutoff);
}
