package zm.iam.security.internal;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import zm.iam.provisioning.ownership.ResourceOwnershipRepository;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * In-memory cache mapping {@code serviceId → set of realms owned by that
 * service}. The realm-scope authorization filter hits this cache on
 * every {@code /internal/**} request, so a naive DB lookup would burn a
 * connection per request; caching keeps the hot path free of I/O.
 *
 * <p>Cache invalidation is driven by {@code ProvisioningService.apply()}
 * — whenever a new manifest lands, that service either (a) registered
 * new realms for an existing owner or (b) planted an entirely new owner.
 * Both cases invalidate the affected serviceId only; other services'
 * entries survive.
 *
 * <p>TTL is a soft safety net (10 min) in case an operator writes to
 * {@code resource_ownership} directly (Terraform, manual SQL) — cache
 * entries eventually age out even without an apply() call.
 */
@Slf4j
@Component
public class OwnedRealmsCache {

    private static final Duration TTL = Duration.ofMinutes(10);

    private final ResourceOwnershipRepository repository;
    private final Cache<String, Set<String>> cache = Caffeine.newBuilder()
            .expireAfterWrite(TTL)
            .maximumSize(1_000)
            .build();

    public OwnedRealmsCache(ResourceOwnershipRepository repository) {
        this.repository = repository;
    }

    /** Set of realms this serviceId owns. Empty set means "owns nothing"
     *  (which is a legitimate answer — the caller then gets 403 for any
     *  realm scope). Never returns null. */
    public Set<String> realmsFor(String serviceId) {
        return cache.get(serviceId, this::loadFromDb);
    }

    /** Drop the cached entry for one service. Called from
     *  {@code ProvisioningService.apply()} after the applied_manifests
     *  row is committed — the next authz check will re-read from DB. */
    public void invalidate(String serviceId) {
        if (serviceId == null) return;
        cache.invalidate(serviceId);
        log.debug("[OwnedRealmsCache] Invalidated entry for serviceId='{}'", serviceId);
    }

    /** Wipe everything — bootstrap-time hygiene + test hook. */
    public void invalidateAll() {
        cache.invalidateAll();
    }

    private Set<String> loadFromDb(String serviceId) {
        List<String> realms = repository.findRealmsOwnedBy(serviceId);
        Set<String> set = new HashSet<>(realms);
        log.debug("[OwnedRealmsCache] Loaded {} realm(s) for serviceId='{}': {}",
                set.size(), serviceId, set);
        return set;
    }
}
