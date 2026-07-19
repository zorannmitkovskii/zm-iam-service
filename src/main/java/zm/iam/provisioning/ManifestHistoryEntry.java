package zm.iam.provisioning;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;

/**
 * One entry in {@code GET /provisioning/manifests/{serviceId}}. Trimmed
 * compared to the raw AppliedManifest row — omits the full
 * manifest_json body to keep the list response light.
 */
public record ManifestHistoryEntry(
        int version,
        String manifestHash,
        OffsetDateTime appliedAt,
        JsonNode changes
) {}
