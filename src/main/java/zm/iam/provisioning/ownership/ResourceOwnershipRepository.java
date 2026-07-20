package zm.iam.provisioning.ownership;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ResourceOwnershipRepository extends JpaRepository<ResourceOwnership, UUID> {

    Optional<ResourceOwnership> findByResourceTypeAndRealmAndResourceName(
            ResourceType resourceType, String realm, String resourceName);

    /** GET /provisioning/ownership?realm=… — return everything in that realm
     *  ordered by resource type then name for a readable operator view. */
    List<ResourceOwnership> findAllByRealmOrderByResourceTypeAscResourceNameAsc(String realm);

    /** All rows for one owning service — used by IAM-09's OwnedRealmsCache
     *  to compute the set of realms the caller is allowed to touch via
     *  {@code /internal/**}. Ordering is stable so cache values are
     *  deterministic across restarts. */
    List<ResourceOwnership> findAllByOwnerServiceOrderByRealmAscResourceNameAsc(String ownerService);

    /** Distinct realms owned by a given service, restricted to the
     *  {@link ResourceType#REALM} rows only. Client-level ownership
     *  inside {@code zm-services} does NOT grant realm-level authority
     *  over {@code zm-services} itself — that realm is IAM's. */
    @Query("select distinct r.realm from ResourceOwnership r " +
            "where r.ownerService = :owner and r.resourceType = zm.iam.provisioning.ownership.ResourceType.REALM")
    List<String> findRealmsOwnedBy(@Param("owner") String owner);
}
