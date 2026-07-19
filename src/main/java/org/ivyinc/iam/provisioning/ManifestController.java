package org.ivyinc.iam.provisioning;

import lombok.extern.slf4j.Slf4j;
import org.ivyinc.iam.common.ApiResponse;
import org.ivyinc.iam.provisioning.dto.ServiceProvisioningManifest;
import org.ivyinc.iam.provisioning.hashing.ManifestHasher;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Provisioning HTTP surface. IAM-03 lands ONE endpoint — a dry-run
 * validator — so services can exercise their manifest against IAM's
 * rules without applying anything. The actual apply endpoint arrives
 * in IAM-04.
 *
 * <p>Accepts both {@code application/json} and {@code application/yaml}
 * bodies. Chooses parser via Content-Type; on any structural failure the
 * error surfaces as a 400 through {@link org.ivyinc.iam.common.GlobalExceptionHandler}.
 */
@Slf4j
@RestController
@RequestMapping("/provisioning/manifests")
public class ManifestController {

    private final ManifestParser parser;
    private final ManifestHasher hasher;

    public ManifestController(ManifestParser parser, ManifestHasher hasher) {
        this.parser = parser;
        this.hasher = hasher;
    }

    /**
     * Dry-run — parse, validate, hash. Returns {@code valid: true} + hash
     * on success; 400 with field-level errors otherwise. Never touches
     * Keycloak.
     */
    @PostMapping(
            value = "/validate",
            consumes = {MediaType.APPLICATION_JSON_VALUE, "application/yaml", "application/x-yaml"}
    )
    public ResponseEntity<ApiResponse<Map<String, Object>>> validate(
            @RequestBody String rawBody,
            @RequestHeader(value = "Content-Type", required = false) String contentType) throws Exception {

        MediaType mt = contentType != null ? MediaType.parseMediaType(contentType) : MediaType.APPLICATION_JSON;
        ServiceProvisioningManifest manifest = parser.parseAndValidate(rawBody, mt);
        String hash = hasher.hash(manifest);
        log.info("[Manifest] Validated manifest for serviceId='{}' version={} → hash={}",
                manifest.serviceId(), manifest.manifestVersion(), hash);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "valid", true,
                "serviceId", manifest.serviceId(),
                "manifestVersion", manifest.manifestVersion(),
                "hash", hash
        )));
    }
}
