package zm.iam.provisioning.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppliedManifestRepository extends JpaRepository<AppliedManifest, UUID> {

    /** Latest applied version for this service, if any. Feeds both the
     *  version gate and the mapper reconciler's "previously declared" set. */
    Optional<AppliedManifest> findFirstByServiceIdOrderByVersionDesc(String serviceId);

    /** Full history, newest first — for GET /provisioning/manifests/{serviceId}. */
    List<AppliedManifest> findAllByServiceIdOrderByVersionDesc(String serviceId);
}
