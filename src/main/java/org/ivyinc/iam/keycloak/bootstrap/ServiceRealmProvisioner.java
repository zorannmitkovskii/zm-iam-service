package org.ivyinc.iam.keycloak.bootstrap;

import lombok.extern.slf4j.Slf4j;
import org.ivyinc.iam.keycloak.KeycloakAdminApi;
import org.ivyinc.iam.keycloak.config.KeycloakProperties;
import org.keycloak.representations.idm.RealmRepresentation;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * The ONLY hardcoded Keycloak bootstrap in IAM: guarantees the
 * {@code zm-services} realm + {@code iam-client} realm role exist before
 * any provisioning request lands. Chicken-and-egg — later reconcilers
 * create service-account clients inside this realm, and those clients
 * can't exist until the realm does.
 *
 * <p>Idempotent by design: every step checks existence before creating.
 * A second run against a fully-provisioned Keycloak is 2 read calls, 0
 * writes.
 *
 * <p>Fires on {@link ApplicationReadyEvent} so
 * {@link org.ivyinc.iam.keycloak.KeycloakAdminSession} is already up.
 * Any failure aborts startup readiness — better than serving requests
 * against a half-provisioned Keycloak.
 *
 * <p>Kill switch: {@code iam.keycloak.self-bootstrap-enabled=false} for
 * environments where the realm was provisioned out-of-band.
 */
@Slf4j
@Component
@ConditionalOnProperty(
        prefix = "iam.keycloak",
        name = "self-bootstrap-enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class ServiceRealmProvisioner {

    private final KeycloakProperties props;
    private final KeycloakAdminApi keycloak;

    public ServiceRealmProvisioner(KeycloakProperties props, KeycloakAdminApi keycloak) {
        this.props = props;
        this.keycloak = keycloak;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void provision() {
        String realmName = props.getZmServicesRealm();
        String roleName = props.getIamClientRole();
        log.info("[ServiceRealmProvisioner] Ensuring realm '{}' and realm role '{}' exist",
                realmName, roleName);

        ensureRealm(realmName);
        ensureRealmRole(realmName, roleName);

        log.info("[ServiceRealmProvisioner] Provisioning complete");
    }

    private void ensureRealm(String realmName) {
        if (keycloak.realmExists(realmName)) {
            log.debug("[ServiceRealmProvisioner] Realm '{}' already exists, skipping", realmName);
            return;
        }
        RealmRepresentation r = new RealmRepresentation();
        r.setRealm(realmName);
        r.setEnabled(true);
        // Service-account-only realm: no human logins, no self-registration,
        // no IdPs. Every principal here is a machine.
        r.setRegistrationAllowed(false);
        r.setLoginWithEmailAllowed(false);
        r.setResetPasswordAllowed(false);
        r.setRememberMe(false);
        r.setDuplicateEmailsAllowed(false);
        r.setVerifyEmail(false);
        keycloak.createRealm(r);
    }

    private void ensureRealmRole(String realmName, String roleName) {
        if (keycloak.realmRoleExists(realmName, roleName)) {
            log.debug("[ServiceRealmProvisioner] Realm role '{}' already exists in '{}', skipping",
                    roleName, realmName);
            return;
        }
        keycloak.createRealmRole(realmName, roleName,
                "Assigned to every zm-* service account so IAM can authorise them uniformly.");
    }
}
