package zm.iam.provisioning.ownership;

import org.springframework.data.jpa.repository.JpaRepository;
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
}
