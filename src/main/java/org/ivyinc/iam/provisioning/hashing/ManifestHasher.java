package org.ivyinc.iam.provisioning.hashing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ivyinc.iam.provisioning.dto.ServiceProvisioningManifest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Deterministic SHA-256 hash of a manifest. Used by IAM-04's
 * {@code applied_manifests.manifest_hash} column so version + hash
 * together detect "same version resent unchanged" vs "same version but
 * mutated body" — the latter is a bug that must fail loudly.
 *
 * <p>Determinism comes from
 * {@link org.ivyinc.iam.provisioning.ManifestObjectMappers}'s
 * {@code manifestCanonicalMapper}: keys sorted alphabetically, empty/null
 * values elided. That means:
 * <pre>
 *   serviceId: a          serviceId: a
 *   manifestVersion: 1    manifestVersion: 1
 *   realms: [...]         realms: [...]
 *
 *   ── same hash ──
 *
 *   manifestVersion: 1    serviceId: a
 *   serviceId: a          realms: [...]
 *   realms: [...]         manifestVersion: 1
 * </pre>
 */
@Component
public class ManifestHasher {

    private final ObjectMapper canonical;

    public ManifestHasher(@Qualifier("manifestCanonicalMapper") ObjectMapper canonical) {
        this.canonical = canonical;
    }

    /** Hex-encoded SHA-256 of the canonical serialisation. */
    public String hash(ServiceProvisioningManifest manifest) {
        byte[] canonicalBytes;
        try {
            canonicalBytes = canonical.writeValueAsBytes(manifest);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not canonicalise manifest for hashing", e);
        }

        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required to be present on every JDK — this can't
            // happen at runtime, but declare it defensively.
            throw new IllegalStateException("SHA-256 not available on this JVM", e);
        }
        byte[] digest = sha256.digest(canonicalBytes);
        return toHex(digest);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
