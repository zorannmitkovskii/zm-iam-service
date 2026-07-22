package zm.iam.publicauth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-IP and per-email counters for register + password-reset requests.
 * Same sliding-window pattern as {@link zm.iam.security.provisioning.ProvisioningRateLimiter}
 * — Caffeine's {@code expireAfterWrite} gives us the window, an atomic
 * counter gives us the increment.
 */
@Component
public class PublicAuthRateLimiter {

    /** Register: 10 attempts per minute per IP + per email. Higher than
     *  provisioning because humans genuinely typo passwords + emails. */
    public static final int REGISTER_LIMIT = 10;
    public static final int PASSWORD_RESET_LIMIT = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final Cache<String, AtomicInteger> ipCache;
    private final Cache<String, AtomicInteger> emailCache;

    public PublicAuthRateLimiter() {
        this.ipCache = Caffeine.newBuilder()
                .expireAfterWrite(WINDOW).maximumSize(10_000).build();
        this.emailCache = Caffeine.newBuilder()
                .expireAfterWrite(WINDOW).maximumSize(10_000).build();
    }

    public boolean isBlocked(String key, String clientIp, String email, int limit) {
        AtomicInteger ipCount = ipCache.getIfPresent(key + "|ip|" + clientIp);
        AtomicInteger emailCount = emailCache.getIfPresent(key + "|email|" + email);
        return (ipCount != null && ipCount.get() >= limit)
                || (emailCount != null && emailCount.get() >= limit);
    }

    public void recordAttempt(String key, String clientIp, String email) {
        ipCache.get(key + "|ip|" + clientIp, k -> new AtomicInteger(0)).incrementAndGet();
        emailCache.get(key + "|email|" + email, k -> new AtomicInteger(0)).incrementAndGet();
    }

    /** Test hook — clear counters between test methods. */
    public void reset() {
        ipCache.invalidateAll();
        emailCache.invalidateAll();
    }
}
