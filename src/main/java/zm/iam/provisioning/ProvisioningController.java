package zm.iam.provisioning;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import zm.iam.common.ApiResponse;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;
import zm.iam.provisioning.persistence.AppliedManifestRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * IAM-04 apply + history surface. IAM-03's dry-run
 * {@link ManifestController} remains at {@code /provisioning/manifests/validate}.
 *
 * <p>No authn yet (deferred to IAM-05) — expose only on the test profile
 * until Spring Security lands. This is called out in the ticket §Не влегува.
 */
@Slf4j
@RestController
@RequestMapping("/provisioning/manifests")
public class ProvisioningController {

    private final ProvisioningService provisioning;
    private final AppliedManifestRepository repository;

    public ProvisioningController(ProvisioningService provisioning,
                                  AppliedManifestRepository repository) {
        this.provisioning = provisioning;
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<ApiResponse<ApplyResult>> apply(
            @Valid @RequestBody ServiceProvisioningManifest manifest) {
        ApplyResult result = provisioning.apply(manifest);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @GetMapping("/{serviceId}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> history(@PathVariable String serviceId) {
        List<ManifestHistoryEntry> history = repository.findAllByServiceIdOrderByVersionDesc(serviceId).stream()
                .map(row -> new ManifestHistoryEntry(
                        row.getVersion(),
                        row.getManifestHash(),
                        row.getAppliedAt(),
                        row.getChanges()))
                .toList();

        Map<String, Object> body = new HashMap<>();
        body.put("serviceId", serviceId);
        body.put("latestVersion", history.isEmpty() ? null : history.get(0).version());
        body.put("history", history);
        return ResponseEntity.ok(ApiResponse.ok(body));
    }

    /** Structured 500 for mid-apply failures. The list of applied-so-far
     *  steps lets the operator see how far the reconciler chain got.
     *  @Transactional on ProvisioningService.apply guarantees
     *  applied_manifests is NOT persisted — safe to retry with the same
     *  version after fixing the root cause. */
    @ExceptionHandler(ProvisioningFailedException.class)
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleProvisioningFailed(
            ProvisioningFailedException ex) {
        Map<String, Object> body = Map.of(
                "reason", ex.getMessage(),
                "appliedSteps", ex.getAppliedSteps()
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("Provisioning failed", body));
    }
}
