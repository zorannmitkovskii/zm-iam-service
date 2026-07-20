package zm.iam.user;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import zm.iam.user.dto.AttributePatchDto;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AttributePatcherTest {

    @Test
    @DisplayName("append: adds new values without duplicating existing ones")
    void appendDeduplicates() {
        Map<String, List<String>> current = Map.of("eventIds", List.of("e1", "e2"));
        var patch = new AttributePatchDto(null, Map.of("eventIds", List.of("e2", "e3")), null);

        var result = AttributePatcher.merge(current, patch);

        assertThat(result.get("eventIds")).containsExactly("e1", "e2", "e3");
    }

    @Test
    @DisplayName("append: idempotent — same values twice → single copy")
    void appendIsIdempotent() {
        Map<String, List<String>> current = Map.of("eventIds", List.of("e1"));
        var patch = new AttributePatchDto(null, Map.of("eventIds", List.of("e1")), null);

        var result = AttributePatcher.merge(current, patch);

        assertThat(result.get("eventIds")).containsExactly("e1");
    }

    @Test
    @DisplayName("remove: existing value → dropped; empty list → key removed entirely")
    void removeCleansUpEmptyLists() {
        Map<String, List<String>> current = Map.of("eventIds", List.of("e1", "e2"));
        var patch = new AttributePatchDto(null, null, Map.of("eventIds", List.of("e1", "e2")));

        var result = AttributePatcher.merge(current, patch);

        assertThat(result).doesNotContainKey("eventIds");
    }

    @Test
    @DisplayName("remove: value not present → no-op, current values preserved")
    void removeIsNoOpForMissingValue() {
        Map<String, List<String>> current = Map.of("eventIds", List.of("e1"));
        var patch = new AttributePatchDto(null, null, Map.of("eventIds", List.of("does-not-exist")));

        var result = AttributePatcher.merge(current, patch);

        assertThat(result.get("eventIds")).containsExactly("e1");
    }

    @Test
    @DisplayName("set: replaces entire value list for a key")
    void setReplacesWhole() {
        Map<String, List<String>> current = Map.of("packages", List.of("basic"));
        var patch = new AttributePatchDto(Map.of("packages", List.of("gold", "platinum")), null, null);

        var result = AttributePatcher.merge(current, patch);

        assertThat(result.get("packages")).containsExactly("gold", "platinum");
    }

    @Test
    @DisplayName("null current → treated as empty map")
    void nullCurrentIsEmpty() {
        var patch = new AttributePatchDto(Map.of("k", List.of("v")), null, null);

        var result = AttributePatcher.merge(null, patch);

        assertThat(result.get("k")).containsExactly("v");
    }

    @Test
    @DisplayName("order applied: set → append → remove within one merge")
    void orderIsSetThenAppendThenRemove() {
        Map<String, List<String>> current = Map.of("k", List.of("old"));
        var patch = new AttributePatchDto(
                Map.of("k", List.of("a", "b")),
                Map.of("m", List.of("m1")),
                Map.of("k", List.of("a")));

        var result = AttributePatcher.merge(current, patch);

        // set put [a,b]; remove dropped a → [b].
        assertThat(result.get("k")).containsExactly("b");
        assertThat(result.get("m")).containsExactly("m1");
    }
}
