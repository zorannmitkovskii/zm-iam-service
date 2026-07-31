package zm.iam.publicauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RealmResolverTest {

    private RealmResolver resolver;

    @BeforeEach
    void setUp() {
        var props = new PublicAuthProperties();
        props.setOriginToRealm(Map.of(
                "ivyevents.mk", "event-app",
                "test.ivyevents.mk", "event-app",
                "localhost", "event-app",
                // Port-qualified keys — how docker-compose configures the
                // local frontends, which all share the host "localhost".
                "localhost:5173", "event-app",
                "localhost:5174", "menu-app",
                "presmetko.mk", "presmetko"));
        props.setAppIdToRealm(Map.of(
                "ivy", "event-app",
                "presmetko", "presmetko"));
        resolver = new RealmResolver(props);
    }

    @Test
    @DisplayName("Known Origin host → mapped realm")
    void knownOriginResolves() {
        assertThat(resolver.resolve("https://test.ivyevents.mk", null))
                .contains("event-app");
    }

    @Test
    @DisplayName("Origin with port + path → port-qualified key matches, path ignored")
    void portQualifiedKeyMatchesAndPathIgnored() {
        assertThat(resolver.resolve("http://localhost:5173/path", null))
                .contains("event-app");
    }

    @Test
    @DisplayName("Two frontends on localhost resolve to their own realms, not a shared one")
    void portDistinguishesFrontendsOnTheSameHost() {
        assertThat(resolver.resolve("http://localhost:5173", null)).contains("event-app");
        assertThat(resolver.resolve("http://localhost:5174", null)).contains("menu-app");
    }

    @Test
    @DisplayName("Unmapped port falls back to the bare-host mapping")
    void unmappedPortFallsBackToHost() {
        assertThat(resolver.resolve("http://localhost:9999", null))
                .contains("event-app");
    }

    @Test
    @DisplayName("Deployed origin on the default port matches its bare-host key")
    void deployedOriginMatchesBareHostKey() {
        assertThat(resolver.resolve("https://ivyevents.mk", null)).contains("event-app");
        assertThat(resolver.resolve("https://presmetko.mk/", null)).contains("presmetko");
    }

    @Test
    @DisplayName("Explicit appId wins even if Origin also matches")
    void explicitAppIdWinsOverOrigin() {
        assertThat(resolver.resolve("https://ivyevents.mk", "presmetko"))
                .contains("presmetko");
    }

    @Test
    @DisplayName("Unknown Origin and no appId → empty (controller turns into 400)")
    void unknownOriginReturnsEmpty() {
        assertThat(resolver.resolve("https://random.example", null)).isEmpty();
    }

    @Test
    @DisplayName("No Origin + no appId → empty")
    void nothingReturnsEmpty() {
        assertThat(resolver.resolve(null, null)).isEmpty();
    }

    @Test
    @DisplayName("Unknown appId → empty (never silently falls back to Origin)")
    void unknownAppIdReturnsEmpty() {
        assertThat(resolver.resolve("https://ivyevents.mk", "unknown"))
                .isEmpty();
    }
}
