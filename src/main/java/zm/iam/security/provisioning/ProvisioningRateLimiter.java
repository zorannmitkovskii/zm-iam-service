package zm.iam.security.provisioning;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-memory sliding-window failure counter per client IP. Only FAILED
 * auth attempts increment the counter; successful requests reset nothing
 * (an ok request is orthogonal to brute-force pressure).
 *
 * <p>Window is 1 minute (per ticket): once an IP accumulates ≥ 10
 * failures in the window, subsequent attempts from that IP return
 * {@code true} from {@link #isBlocked(String)} until the entries age
 * out. Caffeine's {@code expireAfterWrite} gives us the sliding-window
 * behaviour for free.
 *
 * <p>NOT distributed — single-node counter. Fine for IAM's current
 * scale (one instance per env); revisit when we horizontally scale.
 */
@Slf4j
@Component
public class ProvisioningRateLimiter {

    static final int WINDOW_LIMIT = 10;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final Cache<String, AtomicInteger> failuresByIp = Caffeine.newBuilder()
            .expireAfterWrite(WINDOW)
            .maximumSize(10_000)
            .build();

    /** @return {@code true} if this IP has already exceeded the failure
     *  budget in the current window and should be short-circuited to 429. */
    public boolean isBlocked(String clientIp) {
        AtomicInteger count = failuresByIp.getIfPresent(clientIp);
        return count != null && count.get() >= WINDOW_LIMIT;
    }

    /** Record one failed auth attempt for this IP. */
    public void recordFailure(String clientIp) {
        failuresByIp.get(clientIp, k -> new AtomicInteger(0)).incrementAndGet();
    }

    /** Test hook — wipe the counters (mostly for @BeforeEach hygiene). */
    public void reset() {
        failuresByIp.invalidateAll();
    }
}
