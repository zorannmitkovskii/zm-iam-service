package zm.iam.security.provisioning;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * At startup, scans the JVM environment for
 * {@code IAM_PROVISIONING_TOKEN_<SERVICEID>} variables and holds their
 * argon2id hash values in memory. Case: {@code SERVICEID} is upper-snake
 * (env-var convention); the {@code serviceId} in a manifest is
 * lower-kebab. We normalise on lookup.
 *
 * <p>Rotation: env values may be comma-separated (multiple hashes per
 * service) so operators can rotate without downtime.
 *
 * <p>The env supplier is a constructor argument so tests can inject a
 * fixed map without touching the real JVM env.
 */
@Slf4j
@Component
public class TokenRegistry {

    private static final String ENV_PREFIX = "IAM_PROVISIONING_TOKEN_";

    private final Supplier<Map<String, String>> envSupplier;
    private final Map<String, List<String>> serviceIdToHashes = new HashMap<>();

    @Autowired
    public TokenRegistry() {
        this(System::getenv);
    }

    public TokenRegistry(Supplier<Map<String, String>> envSupplier) {
        this.envSupplier = envSupplier;
    }

    @PostConstruct
    void load() {
        int count = 0;
        for (Map.Entry<String, String> e : envSupplier.get().entrySet()) {
            if (!e.getKey().startsWith(ENV_PREFIX)) continue;
            String serviceIdUpper = e.getKey().substring(ENV_PREFIX.length());
            String serviceId = serviceIdUpper.toLowerCase().replace('_', '-');
            List<String> hashes = new ArrayList<>();
            for (String h : e.getValue().split(",")) {
                String trimmed = h.trim();
                if (!trimmed.isEmpty()) hashes.add(trimmed);
            }
            if (!hashes.isEmpty()) {
                serviceIdToHashes.put(serviceId, hashes);
                count += hashes.size();
                log.info("[TokenRegistry] Loaded {} hash(es) for serviceId='{}'", hashes.size(), serviceId);
            }
        }
        log.info("[TokenRegistry] Total {} provisioning tokens loaded across {} services",
                count, serviceIdToHashes.size());
    }

    /** All accepted hashes for this serviceId — empty if the service has
     *  never been provisioned an env token. Rotation callers get every
     *  currently-accepted hash. */
    public List<String> hashesFor(String serviceId) {
        return serviceIdToHashes.getOrDefault(serviceId, Collections.emptyList());
    }

    /** Test hook — replace the in-memory hashes at runtime. */
    void setHashesFor(String serviceId, List<String> hashes) {
        serviceIdToHashes.put(serviceId, List.copyOf(hashes));
    }

    /** Test hook — force a re-scan of a fake env after mutation. */
    static Map<String, String> asMap(String... kv) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    /** Used by tests to build a registry with a canned env, skipping
     *  Spring lifecycle. */
    public static TokenRegistry ofEnv(Map<String, String> env) {
        TokenRegistry r = new TokenRegistry(() -> env);
        r.load();
        return r;
    }

    /** Package-private accessor for tests inspecting loaded state. */
    Map<String, List<String>> snapshot() {
        Map<String, List<String>> out = new HashMap<>();
        for (Map.Entry<String, List<String>> e : serviceIdToHashes.entrySet()) {
            out.put(e.getKey(), new ArrayList<>(e.getValue()));
        }
        return out;
    }

    // Package-private helper for reflection-free test setup.
    @SuppressWarnings("unused")
    static List<String> splitCsv(String csv) {
        return Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
