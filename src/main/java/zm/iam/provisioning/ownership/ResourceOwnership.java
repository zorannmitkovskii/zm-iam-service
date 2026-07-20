package zm.iam.provisioning.ownership;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * One row per (resource kind, realm, resource name) — the service that
 * planted it first owns it. Attempts by other services to touch the
 * same resource fail with a 409 conflict BEFORE any Keycloak write.
 */
@Data
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(
        name = "resource_ownership",
        uniqueConstraints = @UniqueConstraint(
                name = "resource_ownership_type_realm_name_uk",
                columnNames = {"resource_type", "realm", "resource_name"}
        )
)
public class ResourceOwnership {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "resource_type", nullable = false, length = 16)
    private ResourceType resourceType;

    @Column(nullable = false, length = 64)
    private String realm;

    @Column(name = "resource_name", nullable = false, length = 255)
    private String resourceName;

    @Column(name = "owner_service", nullable = false, length = 64)
    private String ownerService;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}
