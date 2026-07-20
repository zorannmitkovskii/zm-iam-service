package zm.iam.audit;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * One row per audited operation. Append-only in code — nothing UPDATEs
 * or DELETEs except the retention job. Column semantics documented in
 * {@code V4__audit_log.sql}.
 */
@Data
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(
        name = "audit_log",
        indexes = {
                @Index(name = "idx_audit_log_occurred_at_desc", columnList = "occurred_at DESC"),
                @Index(name = "idx_audit_log_target", columnList = "target_type, target_id"),
                @Index(name = "idx_audit_log_realm_occurred", columnList = "realm, occurred_at DESC")
        }
)
public class AuditLogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "occurred_at", nullable = false)
    private OffsetDateTime occurredAt;

    @Column(nullable = false, length = 128)
    private String caller;

    @Column(length = 64)
    private String realm;

    @Enumerated(EnumType.STRING)
    @Column(name = "target_type", nullable = false, length = 32)
    private TargetType targetType;

    @Column(name = "target_id", length = 255)
    private String targetId;

    @Column(nullable = false, length = 64)
    private String operation;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private JsonNode detail;

    @Column(nullable = false)
    private boolean success;
}
