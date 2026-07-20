package zm.iam.security.provisioning;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TokenRegistryTest {

    @Test
    @DisplayName("Loads IAM_PROVISIONING_TOKEN_<SERVICEID> vars, normalising to kebab-case")
    void loadsAndNormalisesServiceIds() {
        TokenRegistry r = TokenRegistry.ofEnv(Map.of(
                "IAM_PROVISIONING_TOKEN_IVY_EVENTS_BE", "$argon2id$hash1",
                "UNRELATED_ENV", "ignored"));
        assertThat(r.hashesFor("ivy-events-be")).containsExactly("$argon2id$hash1");
        assertThat(r.hashesFor("presmetko-be")).isEmpty();
    }

    @Test
    @DisplayName("Comma-separated hashes → rotation support")
    void supportsRotation() {
        TokenRegistry r = TokenRegistry.ofEnv(Map.of(
                "IAM_PROVISIONING_TOKEN_SVC", "hash-old,hash-new"));
        assertThat(r.hashesFor("svc")).containsExactly("hash-old", "hash-new");
    }

    @Test
    @DisplayName("Empty entries in the comma list are dropped")
    void tolerantOfBlanks() {
        TokenRegistry r = TokenRegistry.ofEnv(Map.of(
                "IAM_PROVISIONING_TOKEN_SVC", "hash-a,, ,hash-b"));
        assertThat(r.hashesFor("svc")).containsExactly("hash-a", "hash-b");
    }
}
