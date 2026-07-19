package org.ivyinc.iam.provisioning.persistence;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * One row per successful manifest apply. Own timestamp semantics
 * (applied_at, not created/updated) so this entity doesn't extend
 * BaseEntity. See V2__applied_manifests.sql for column intent.
 */
@Data
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(
        name = "applied_manifests",
        uniqueConstraints = @UniqueConstraint(
                name = "applied_manifests_svc_ver_uk",
                columnNames = {"service_id", "version"}
        )
)
public class AppliedManifest {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "service_id", nullable = false, length = 64)
    private String serviceId;

    @Column(nullable = false)
    private Integer version;

    @Column(name = "manifest_hash", nullable = false, length = 64)
    private String manifestHash;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "manifest_json", nullable = false, columnDefinition = "jsonb")
    private JsonNode manifestJson;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private JsonNode changes;

    @Column(name = "applied_at", nullable = false)
    private OffsetDateTime appliedAt;
}
