package zm.iam.user.dto;

import java.util.List;
import java.util.Map;

/**
 * Three buckets applied in the order set → append → remove. A null bucket
 * means "no operation for it", which is why they are nullable rather than
 * defaulted to empty maps: an empty map and an absent one would otherwise be
 * indistinguishable, and "replace this attribute with nothing" is a different
 * instruction from "leave it alone".
 *
 * <p>Append exists so a caller can add one event to {@code eventIds} without
 * first reading what is there. Doing it any other way is a read-modify-write
 * across a network, and two events created at the same moment lose one.
 */
public record AttributePatchRequest(
        Map<String, List<String>> set,
        Map<String, List<String>> append,
        Map<String, List<String>> remove
) {}
