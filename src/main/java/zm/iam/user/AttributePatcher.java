package zm.iam.user;

import zm.iam.user.dto.AttributePatchDto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure function that merges a patch onto a snapshot of a user's current
 * attributes. Kept static + side-effect-free so unit tests hit every
 * branch without a Spring context or a Keycloak.
 *
 * <p>Order matters:
 * <ol>
 *   <li>Copy current (defensive — never mutate the caller's map).</li>
 *   <li>Apply {@code set} — replaces each key's whole value list.</li>
 *   <li>Apply {@code append} — adds values, skipping duplicates.</li>
 *   <li>Apply {@code remove} — drops matching values; if a key ends up
 *       empty it's removed from the result so Keycloak isn't handed an
 *       attribute with zero values (which it treats as delete anyway,
 *       but this keeps the payload clean).</li>
 * </ol>
 */
public final class AttributePatcher {

    private AttributePatcher() {}

    public static Map<String, List<String>> merge(Map<String, List<String>> current, AttributePatchDto patch) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        if (current != null) {
            current.forEach((k, v) -> result.put(k, v == null ? new ArrayList<>() : new ArrayList<>(v)));
        }
        if (patch == null) return result;

        if (patch.set() != null) {
            patch.set().forEach((k, v) -> result.put(k, v == null ? new ArrayList<>() : new ArrayList<>(v)));
        }

        if (patch.append() != null) {
            patch.append().forEach((k, values) -> {
                List<String> existing = result.computeIfAbsent(k, x -> new ArrayList<>());
                if (values == null) return;
                for (String v : values) {
                    if (!existing.contains(v)) existing.add(v);
                }
            });
        }

        if (patch.remove() != null) {
            patch.remove().forEach((k, values) -> {
                List<String> existing = result.get(k);
                if (existing == null || values == null) return;
                existing.removeAll(values);
                if (existing.isEmpty()) result.remove(k);
            });
        }

        // Convert to a plain HashMap for callers that expect the standard shape.
        return new HashMap<>(result);
    }
}
