package zm.iam.publicauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sliding-window semantics for the register / password-reset counter.
 * Same shape as {@link zm.iam.security.provisioning.ProvisioningRateLimiter} —
 * per-IP and per-email counters, either dimension trips the block.
 */
class PublicAuthRateLimiterTest {

    private PublicAuthRateLimiter rl;

    @BeforeEach
    void setUp() {
        rl = new PublicAuthRateLimiter();
    }

    @Test
    @DisplayName("Under the register limit → not blocked")
    void underLimitAllowed() {
        for (int i = 0; i < PublicAuthRateLimiter.REGISTER_LIMIT - 1; i++) {
            rl.recordAttempt("register", "1.2.3.4", "a@b.mk");
        }
        assertThat(rl.isBlocked("register", "1.2.3.4", "a@b.mk",
                PublicAuthRateLimiter.REGISTER_LIMIT)).isFalse();
    }

    @Test
    @DisplayName("At the register limit → blocked")
    void atLimitBlocked() {
        for (int i = 0; i < PublicAuthRateLimiter.REGISTER_LIMIT; i++) {
            rl.recordAttempt("register", "1.2.3.4", "a@b.mk");
        }
        assertThat(rl.isBlocked("register", "1.2.3.4", "a@b.mk",
                PublicAuthRateLimiter.REGISTER_LIMIT)).isTrue();
    }

    @Test
    @DisplayName("Same IP but different email counts EACH — either dimension trips")
    void ipTripsEvenIfEmailChanges() {
        for (int i = 0; i < PublicAuthRateLimiter.REGISTER_LIMIT; i++) {
            rl.recordAttempt("register", "1.2.3.4", "a" + i + "@b.mk");
        }
        // Same IP, fresh email → still blocked because ip counter maxed.
        assertThat(rl.isBlocked("register", "1.2.3.4", "brand-new@b.mk",
                PublicAuthRateLimiter.REGISTER_LIMIT)).isTrue();
    }

    @Test
    @DisplayName("Same email from different IPs — email dimension trips")
    void emailTripsEvenIfIpRotates() {
        for (int i = 0; i < PublicAuthRateLimiter.REGISTER_LIMIT; i++) {
            rl.recordAttempt("register", "1.2.3." + i, "a@b.mk");
        }
        assertThat(rl.isBlocked("register", "9.9.9.9", "a@b.mk",
                PublicAuthRateLimiter.REGISTER_LIMIT)).isTrue();
    }

    @Test
    @DisplayName("Different key namespaces (register vs pwreset) share nothing")
    void keysAreNamespaced() {
        for (int i = 0; i < PublicAuthRateLimiter.REGISTER_LIMIT; i++) {
            rl.recordAttempt("register", "1.2.3.4", "a@b.mk");
        }
        assertThat(rl.isBlocked("pwreset", "1.2.3.4", "a@b.mk",
                PublicAuthRateLimiter.PASSWORD_RESET_LIMIT)).isFalse();
    }

    @Test
    @DisplayName("reset() drops all counters (test hygiene)")
    void resetClears() {
        for (int i = 0; i < PublicAuthRateLimiter.REGISTER_LIMIT; i++) {
            rl.recordAttempt("register", "1.2.3.4", "a@b.mk");
        }
        rl.reset();
        assertThat(rl.isBlocked("register", "1.2.3.4", "a@b.mk",
                PublicAuthRateLimiter.REGISTER_LIMIT)).isFalse();
    }
}
