package zm.iam.user;

import org.springframework.stereotype.Component;

/**
 * Per-{@code (realm, userId)} monitor for read-modify-write blocks
 * (attribute patch, role diff). Keycloak has no ETag on users, so
 * concurrent PATCH calls against the same user would race
 * fetch→merge→update. IAM is the SINGLE write path, so a JVM-local
 * stripe is enough to serialise callers.
 *
 * <p>64 stripes → low contention across many users, but same
 * {@code (realm, userId)} always maps to the same monitor. If Ivy ever
 * scales IAM horizontally we swap for a Postgres advisory lock or
 * per-user row lock — noted in the ticket as a known limitation.
 */
@Component
public class UserStripedLock {

    private static final int STRIPES = 64;

    private final Object[] locks;

    public UserStripedLock() {
        this.locks = new Object[STRIPES];
        for (int i = 0; i < STRIPES; i++) locks[i] = new Object();
    }

    public Object lockFor(String realm, String userId) {
        int hash = (realm + ":" + userId).hashCode();
        return locks[Math.floorMod(hash, STRIPES)];
    }
}
