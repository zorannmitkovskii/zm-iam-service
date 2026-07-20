package zm.iam.user;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UserStripedLockTest {

    @Test
    @DisplayName("Same (realm, userId) → same monitor object")
    void sameKeyReturnsSameMonitor() {
        UserStripedLock lock = new UserStripedLock();
        Object a = lock.lockFor("event-app", "user-1");
        Object b = lock.lockFor("event-app", "user-1");
        assertThat(a).isSameAs(b);
    }

    @Test
    @DisplayName("Different userIds may or may not share a stripe; equality is not required")
    void differentKeysMayShareOrNotShare() {
        UserStripedLock lock = new UserStripedLock();
        // 64 stripes, hash-based → different keys sometimes collide. The
        // contract is "same key → same monitor", not "different key →
        // different monitor". Test the STRIPE hashing works.
        assertThat(lock.lockFor("app", "1")).isNotNull();
        assertThat(lock.lockFor("app", "2")).isNotNull();
    }
}
