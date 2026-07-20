package zm.iam.user.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.AssertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Three atomic operations against a user's multi-valued attributes.
 * Applied in the order {@code set} → {@code append} → {@code remove}
 * against the CURRENT Keycloak state, then written back in a single
 * update.
 *
 * <ul>
 *   <li>{@code set} — replace the whole value list for a key.</li>
 *   <li>{@code append} — add values without duplicating existing
 *       entries (idempotent).</li>
 *   <li>{@code remove} — remove specific values; missing values are
 *       no-ops (idempotent).</li>
 * </ul>
 *
 * <p>A key appearing in BOTH {@code set} and {@code append} is a client
 * bug (ambiguous semantics) — reject with 400 client-side via
 * {@link AssertTrue} before any Keycloak call.
 *
 * <p>Null maps mean "no operation for this bucket"; empty maps are
 * treated the same.
 */
public record AttributePatchDto(
        Map<String, List<String>> set,
        Map<String, List<String>> append,
        Map<String, List<String>> remove
) {

    @JsonIgnore
    @AssertTrue(message = "a key must not appear in both 'set' and 'append' — choose one")
    public boolean isSetAppendDisjoint() {
        if (set == null || append == null) return true;
        Set<String> intersection = new HashSet<>(set.keySet());
        intersection.retainAll(append.keySet());
        return intersection.isEmpty();
    }
}
