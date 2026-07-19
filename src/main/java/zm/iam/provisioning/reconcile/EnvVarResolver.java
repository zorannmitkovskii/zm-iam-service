package zm.iam.provisioning.reconcile;

import org.springframework.stereotype.Component;

/**
 * Wraps {@link System#getenv(String)} so tests can inject a fake without
 * touching the JVM env. Small on purpose — the value of the wrapper is
 * "we can force the IdP env-ref lookup to miss in a test and verify
 * IdpReconciler bails BEFORE any Keycloak write".
 */
@Component
public class EnvVarResolver {
    public String get(String name) {
        return System.getenv(name);
    }
}
