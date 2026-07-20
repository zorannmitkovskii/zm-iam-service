package zm.iam.security.provisioning;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProvisioningRateLimiterTest {

    @Test
    @DisplayName("Under the limit → not blocked")
    void underLimitAllowed() {
        ProvisioningRateLimiter rl = new ProvisioningRateLimiter();
        for (int i = 0; i < ProvisioningRateLimiter.WINDOW_LIMIT - 1; i++) {
            rl.recordFailure("1.2.3.4");
        }
        assertThat(rl.isBlocked("1.2.3.4")).isFalse();
    }

    @Test
    @DisplayName("At the limit → blocked")
    void atLimitBlocked() {
        ProvisioningRateLimiter rl = new ProvisioningRateLimiter();
        for (int i = 0; i < ProvisioningRateLimiter.WINDOW_LIMIT; i++) {
            rl.recordFailure("1.2.3.4");
        }
        assertThat(rl.isBlocked("1.2.3.4")).isTrue();
    }

    @Test
    @DisplayName("Counters are per-IP")
    void perIp() {
        ProvisioningRateLimiter rl = new ProvisioningRateLimiter();
        for (int i = 0; i < ProvisioningRateLimiter.WINDOW_LIMIT; i++) {
            rl.recordFailure("1.2.3.4");
        }
        assertThat(rl.isBlocked("1.2.3.4")).isTrue();
        assertThat(rl.isBlocked("5.6.7.8")).isFalse();
    }
}
