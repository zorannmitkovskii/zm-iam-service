package zm.iam.provisioning.hashing;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ManifestHasher must be stable across cosmetic reorderings and must
 * change when any semantic value changes.
 */
class ManifestHasherTest {

    private final ManifestHasher hasher = new ManifestHasher(canonicalMapper());

    // ── Stability across "identical" reconstructions ────────────

    @Test
    @DisplayName("Two equal manifests → same hash")
    void equalManifestsHashSame() {
        var a = fullManifest();
        var b = fullManifest();
        assertThat(hasher.hash(a)).isEqualTo(hasher.hash(b));
    }

    // ── Detects semantic changes ─────────────────────────────────

    @Test
    @DisplayName("Different serviceId → different hash")
    void serviceIdChangeChangesHash() {
        var a = fullManifest();
        var b = new ServiceProvisioningManifest("other-svc", 3, a.realms());
        assertThat(hasher.hash(a)).isNotEqualTo(hasher.hash(b));
    }

    @Test
    @DisplayName("Different manifestVersion → different hash")
    void versionChangeChangesHash() {
        var a = fullManifest();
        var b = new ServiceProvisioningManifest(a.serviceId(), 99, a.realms());
        assertThat(hasher.hash(a)).isNotEqualTo(hasher.hash(b));
    }

    @Test
    @DisplayName("Different client redirectUri → different hash")
    void redirectUriChangeChangesHash() {
        var a = fullManifest();
        var mutatedClient = new ClientDeclaration(
                "eventFE", ClientType.PUBLIC, true,
                List.of("https://evil.com/*"),
                null, null, null, null, null);
        var b = new ServiceProvisioningManifest(a.serviceId(), a.manifestVersion(), List.of(
                new RealmDeclaration("event-app", null, List.of(mutatedClient),
                        null, null, null)));
        assertThat(hasher.hash(a)).isNotEqualTo(hasher.hash(b));
    }

    // ── Hex format ────────────────────────────────────────────────

    @Test
    @DisplayName("Hash is 64 hex chars (SHA-256)")
    void hashIsSixtyFourHex() {
        assertThat(hasher.hash(fullManifest()))
                .hasSize(64)
                .matches("[0-9a-f]+");
    }

    // ── helpers ──────────────────────────────────────────────────

    private static ServiceProvisioningManifest fullManifest() {
        var client = new ClientDeclaration(
                "eventFE", ClientType.PUBLIC, true,
                List.of("https://ivyevents.mk/*"),
                List.of("+"), null, null, null, null);
        return new ServiceProvisioningManifest("ivy-events-be", 3, List.of(
                new RealmDeclaration("event-app", null, List.of(client),
                        List.of("USER"), null, null)));
    }

    private static ObjectMapper canonicalMapper() {
        ObjectMapper m = new ObjectMapper();
        m.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        m.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
        m.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        return m;
    }
}
