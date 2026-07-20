package zm.iam.provisioning.ownership;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zm.iam.common.ApiResponse;

import java.util.List;
import java.util.Map;

/**
 * Operator-facing read endpoint for ownership state. Useful during
 * onboarding of a second service or debugging a 409 — "why does IAM
 * think {@code presmetko-be} owns this?"
 */
@Slf4j
@RestController
@RequestMapping("/provisioning/ownership")
public class OwnershipController {

    private final ResourceOwnershipRepository repository;

    public OwnershipController(ResourceOwnershipRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> byRealm(@RequestParam String realm) {
        List<Row> rows = repository.findAllByRealmOrderByResourceTypeAscResourceNameAsc(realm).stream()
                .map(r -> new Row(r.getResourceType(), r.getResourceName(), r.getOwnerService()))
                .toList();
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "realm", realm,
                "resources", rows
        )));
    }

    /** Lightweight response projection — drops JPA metadata (id, timestamp)
     *  the operator doesn't care about. */
    public record Row(ResourceType resourceType, String resourceName, String ownerService) {}
}
