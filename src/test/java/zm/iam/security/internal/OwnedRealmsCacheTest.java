package zm.iam.security.internal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import zm.iam.provisioning.ownership.ResourceOwnershipRepository;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * Cache-behaviour tests. We're not testing Caffeine itself — we're
 * asserting that the cache class hits the repo exactly once per
 * serviceId, and that {@link OwnedRealmsCache#invalidate(String)}
 * forces the next lookup to re-hit the DB (i.e. IAM-09's post-apply
 * hook actually works).
 */
class OwnedRealmsCacheTest {

    private ResourceOwnershipRepository repository;
    private OwnedRealmsCache cache;

    @BeforeEach
    void setUp() {
        repository = mock(ResourceOwnershipRepository.class);
        cache = new OwnedRealmsCache(repository);
    }

    @Test
    @DisplayName("First read hits DB; second read is served from cache")
    void secondReadIsCached() {
        when(repository.findRealmsOwnedBy("ivy-events-be"))
                .thenReturn(List.of("event-app"));

        Set<String> first = cache.realmsFor("ivy-events-be");
        Set<String> second = cache.realmsFor("ivy-events-be");

        assertThat(first).containsExactly("event-app");
        assertThat(second).containsExactly("event-app");
        verify(repository, times(1)).findRealmsOwnedBy("ivy-events-be");
        verifyNoMoreInteractions(repository);
    }

    @Test
    @DisplayName("Empty ownership → empty set (never null)")
    void emptyOwnershipReturnsEmptySet() {
        when(repository.findRealmsOwnedBy("no-owner-svc")).thenReturn(List.of());

        Set<String> realms = cache.realmsFor("no-owner-svc");

        assertThat(realms).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("invalidate() drops the entry so the next call re-reads")
    void invalidateForcesReload() {
        when(repository.findRealmsOwnedBy("ivy-events-be"))
                .thenReturn(List.of("event-app"), List.of("event-app", "new-realm"));

        Set<String> v1 = cache.realmsFor("ivy-events-be");
        cache.invalidate("ivy-events-be");
        Set<String> v2 = cache.realmsFor("ivy-events-be");

        assertThat(v1).containsExactly("event-app");
        assertThat(v2).containsExactlyInAnyOrder("event-app", "new-realm");
        verify(repository, times(2)).findRealmsOwnedBy("ivy-events-be");
    }

    @Test
    @DisplayName("invalidate(null) is a safe no-op")
    void invalidateNullIsNoop() {
        cache.invalidate(null);
        // just no exception
    }

    @Test
    @DisplayName("invalidateAll() drops every entry")
    void invalidateAllForcesReload() {
        when(repository.findRealmsOwnedBy("svc-a")).thenReturn(List.of("a"));
        when(repository.findRealmsOwnedBy("svc-b")).thenReturn(List.of("b"));

        cache.realmsFor("svc-a");
        cache.realmsFor("svc-b");
        cache.invalidateAll();
        cache.realmsFor("svc-a");
        cache.realmsFor("svc-b");

        verify(repository, times(2)).findRealmsOwnedBy("svc-a");
        verify(repository, times(2)).findRealmsOwnedBy("svc-b");
    }

    @Test
    @DisplayName("Different serviceIds are cached independently")
    void independentCacheEntries() {
        when(repository.findRealmsOwnedBy("ivy-events-be")).thenReturn(List.of("event-app"));
        when(repository.findRealmsOwnedBy("presmetko-be")).thenReturn(List.of("presmetko"));

        assertThat(cache.realmsFor("ivy-events-be")).containsExactly("event-app");
        assertThat(cache.realmsFor("presmetko-be")).containsExactly("presmetko");
        assertThat(cache.realmsFor("ivy-events-be")).containsExactly("event-app");

        verify(repository, times(1)).findRealmsOwnedBy("ivy-events-be");
        verify(repository, times(1)).findRealmsOwnedBy("presmetko-be");
    }
}
